#include <jni.h>
#include <elf.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <cxxabi.h>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <unordered_map>

#include <capstone/capstone.h>

// Helper to convert address to hex string
std::string to_hex_string(uint64_t val) {
    std::stringstream ss;
    ss << "0x" << std::uppercase << std::hex << val;
    return ss.str();
}

// Structure to hold parsed function info
struct ParsedSymbol {
    std::string address;
    std::string name;
    std::string size;
    std::string bind;
    std::string type;
    int index;
};

// Proper standard Itanium demangler using compiler runtime abi::__cxa_demangle
std::string simple_demangle(const std::string& mangled) {
    int status = 0;
    char *demangled = abi::__cxa_demangle(mangled.c_str(), nullptr, nullptr, &status);
    if (status == 0 && demangled != nullptr) {
        std::string result(demangled);
        free(demangled);
        return result;
    }
    return mangled;
}

std::string sanitize_function_name(const std::string& name) {
    std::string clean = "";
    for (char c : name) {
        if (isalnum(c) || c == '_') {
            clean += c;
        } else {
            clean += '_';
        }
    }
    std::string final_clean = "";
    for (char c : clean) {
        if (c == '_' && !final_clean.empty() && final_clean.back() == '_') {
            continue;
        }
        final_clean += c;
    }
    return final_clean;
}

struct GlobalData {
    uint64_t virtualAddress;
    std::string name;
    std::string type;
    std::string value;
};

std::vector<GlobalData> extract_strings_and_data(std::ifstream& inFile, uint64_t offset, uint64_t size, uint64_t vaddr, const std::string& sectionName) {
    std::vector<GlobalData> list;
    if (size == 0 || offset == 0) return list;

    std::streampos originalPos = inFile.tellg();

    std::vector<uint8_t> buffer(size);
    inFile.seekg(offset, std::ios::beg);
    inFile.read(reinterpret_cast<char*>(buffer.data()), size);

    inFile.seekg(originalPos, std::ios::beg);

    size_t i = 0;
    while (i < size) {
        size_t start = i;
        while (i < size && buffer[i] >= 32 && buffer[i] <= 126) {
            i++;
        }
        if (i < size && buffer[i] == '\0' && (i - start) >= 4) {
            std::string str(reinterpret_cast<char*>(&buffer[start]), i - start);
            std::string escaped = "";
            for (char c : str) {
                if (c == '"') escaped += "\\\"";
                else if (c == '\\') escaped += "\\\\";
                else if (c == '\n') escaped += "\\n";
                else if (c == '\r') escaped += "\\r";
                else if (c == '\t') escaped += "\\t";
                else escaped += c;
            }
            list.push_back({
                vaddr + start,
                "str_" + to_hex_string(vaddr + start).substr(2),
                "const char",
                "\"" + escaped + "\""
            });
            i++;
        } else {
            i = start + 1;
        }
    }
    return list;
}

// AST helper to decompile ARM64 instructions into pseudocode
std::string decompile_instructions(const cs_insn *insns, size_t count) {
    std::stringstream ps;
    std::string current_cmp_reg = "";
    std::string current_cmp_val = "";
    bool has_cmp = false;

    ps << "void decompiled_function() {\n";
    
    for (size_t i = 0; i < count; ++i) {
        const cs_insn &insn = insns[i];
        std::string mnemonic = insn.mnemonic;
        std::string op_str = insn.op_str;

        if (mnemonic == "cmp") {
            size_t comma = op_str.find(',');
            if (comma != std::string::npos) {
                current_cmp_reg = op_str.substr(0, comma);
                size_t hash = op_str.find('#', comma);
                if (hash != std::string::npos) {
                    current_cmp_val = op_str.substr(hash + 1);
                } else {
                    current_cmp_val = op_str.substr(comma + 2);
                }
                has_cmp = true;
            }
        } 
        else if (mnemonic.rfind("b.", 0) == 0) {
            std::string cond = mnemonic.substr(2);
            std::string label = op_str;
            if (has_cmp) {
                std::string op = "==";
                if (cond == "ne") op = "!=";
                else if (cond == "lt") op = "<";
                else if (cond == "le") op = "<=";
                else if (cond == "gt") op = ">";
                else if (cond == "ge") op = ">=";

                ps << "    if (" << current_cmp_reg << " " << op << " " << current_cmp_val << ") {\n";
                ps << "        goto " << label << ";\n";
                ps << "    }\n";
            } else {
                ps << "    if (" << cond << ") {\n";
                ps << "        goto " << label << ";\n";
                ps << "    }\n";
            }
        }
        else if (mnemonic == "b") {
            ps << "    goto " << op_str << ";\n";
        }
        else if (mnemonic == "bl") {
            ps << "    function_" << op_str << "();\n";
        }
        else if (mnemonic == "mov") {
            size_t comma = op_str.find(',');
            if (comma != std::string::npos) {
                std::string dest = op_str.substr(0, comma);
                std::string src = op_str.substr(comma + 2);
                ps << "    " << dest << " = " << src << ";\n";
            }
        }
        else if (mnemonic == "add" || mnemonic == "sub") {
            size_t first_comma = op_str.find(',');
            if (first_comma != std::string::npos) {
                std::string rd = op_str.substr(0, first_comma);
                size_t second_comma = op_str.find(',', first_comma + 1);
                if (second_comma != std::string::npos) {
                    std::string rn = op_str.substr(first_comma + 2, second_comma - (first_comma + 2));
                    std::string imm = op_str.substr(second_comma + 2);
                    char op = (mnemonic == "add") ? '+' : '-';
                    ps << "    " << rd << " = " << rn << " " << op << " " << imm << ";\n";
                }
            }
        }
        else if (mnemonic == "ldr") {
            size_t first_comma = op_str.find(',');
            if (first_comma != std::string::npos) {
                std::string rd = op_str.substr(0, first_comma);
                std::string mem = op_str.substr(first_comma + 2);
                ps << "    " << rd << " = *" << mem << ";\n";
            }
        }
        else if (mnemonic == "str") {
            size_t first_comma = op_str.find(',');
            if (first_comma != std::string::npos) {
                std::string rd = op_str.substr(0, first_comma);
                std::string mem = op_str.substr(first_comma + 2);
                ps << "    *" << mem << " = " << rd << ";\n";
            }
        }
        else if (mnemonic == "ret") {
            ps << "    return;\n";
        }
    }

    ps << "}\n";
    return ps.str();
}

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_example_ElfParser_demangleNative(JNIEnv *env, jobject thiz, jstring mangled) {
    if (!mangled) return nullptr;
    const char *mangled_str = env->GetStringUTFChars(mangled, nullptr);
    if (!mangled_str) return mangled;

    int status = 0;
    char *demangled = abi::__cxa_demangle(mangled_str, nullptr, nullptr, &status);
    env->ReleaseStringUTFChars(mangled, mangled_str);

    if (status == 0 && demangled != nullptr) {
        jstring result = env->NewStringUTF(demangled);
        free(demangled);
        return result;
    } else {
        return mangled;
    }
}

JNIEXPORT jobject JNICALL
Java_com_example_ElfParser_parseElfNative(JNIEnv *env, jobject thiz, jstring file_path) {
    jclass list_class = env->FindClass("java/util/ArrayList");
    jmethodID list_init = env->GetMethodID(list_class, "<init>", "()V");
    jobject list_obj = env->NewObject(list_class, list_init);
    jmethodID list_add = env->GetMethodID(list_class, "add", "(Ljava/lang/Object;)Z");

    jclass func_class = env->FindClass("com/example/ElfParser$ElfFunction");
    jmethodID func_init = env->GetMethodID(func_class, "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V");

    const char *path = env->GetStringUTFChars(file_path, nullptr);
    if (!path) return list_obj;

    int fd = open(path, O_RDONLY);
    env->ReleaseStringUTFChars(file_path, path);
    if (fd < 0) return list_obj;

    struct stat sb;
    if (fstat(fd, &sb) < 0) {
        close(fd);
        return list_obj;
    }

    size_t length = sb.st_size;
    if (length < sizeof(Elf32_Ehdr)) {
        close(fd);
        return list_obj;
    }

    void *addr = mmap(nullptr, length, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (addr == MAP_FAILED) {
        return list_obj;
    }

    unsigned char *elf_bytes = static_cast<unsigned char *>(addr);
    if (elf_bytes[0] != 0x7F || elf_bytes[1] != 'E' || elf_bytes[2] != 'L' || elf_bytes[3] != 'F') {
        munmap(addr, length);
        return list_obj;
    }

    unsigned char elf_class = elf_bytes[4];
    std::vector<ParsedSymbol> parsed_symbols;

    if (elf_class == 2) {
        if (length >= sizeof(Elf64_Ehdr)) {
            Elf64_Ehdr *ehdr = reinterpret_cast<Elf64_Ehdr *>(elf_bytes);
            Elf64_Shdr *shdr = reinterpret_cast<Elf64_Shdr *>(elf_bytes + ehdr->e_shoff);

            uint64_t symtab_offset = 0;
            uint64_t symtab_size = 0;
            uint64_t symtab_entsize = 0;
            uint64_t strtab_offset = 0;
            uint64_t strtab_size = 0;

            uint64_t dynsym_offset = 0;
            uint64_t dynsym_size = 0;
            uint64_t dynsym_entsize = 0;
            uint64_t dynstr_offset = 0;
            uint64_t dynstr_size = 0;

            for (int i = 0; i < ehdr->e_shnum; i++) {
                uint64_t sh_offset = ehdr->e_shoff + i * ehdr->e_shentsize;
                if (sh_offset + sizeof(Elf64_Shdr) > length) break;

                Elf64_Shdr *sec = reinterpret_cast<Elf64_Shdr *>(elf_bytes + sh_offset);
                if (sec->sh_type == SHT_SYMTAB) {
                    symtab_offset = sec->sh_offset;
                    symtab_size = sec->sh_size;
                    symtab_entsize = sec->sh_entsize;
                } else if (sec->sh_type == SHT_STRTAB && i != ehdr->e_shstrndx) {
                    strtab_offset = sec->sh_offset;
                    strtab_size = sec->sh_size;
                } else if (sec->sh_type == SHT_DYNSYM) {
                    dynsym_offset = sec->sh_offset;
                    dynsym_size = sec->sh_size;
                    dynsym_entsize = sec->sh_entsize;
                }
            }

            for (int i = 0; i < ehdr->e_shnum; i++) {
                uint64_t sh_offset = ehdr->e_shoff + i * ehdr->e_shentsize;
                if (sh_offset + sizeof(Elf64_Shdr) > length) break;
                Elf64_Shdr *sec = reinterpret_cast<Elf64_Shdr *>(elf_bytes + sh_offset);
                if (sec->sh_type == SHT_STRTAB && i != ehdr->e_shstrndx && sec->sh_offset != strtab_offset) {
                    dynstr_offset = sec->sh_offset;
                    dynstr_size = sec->sh_size;
                }
            }

            uint64_t target_sym_offset = (symtab_offset != 0) ? symtab_offset : dynsym_offset;
            uint64_t target_sym_size = (symtab_offset != 0) ? symtab_size : dynsym_size;
            uint64_t target_sym_entsize = (symtab_offset != 0) ? symtab_entsize : dynsym_entsize;
            uint64_t target_str_offset = (symtab_offset != 0) ? strtab_offset : dynstr_offset;
            uint64_t target_str_size = (symtab_offset != 0) ? strtab_size : dynstr_size;

            if (target_sym_offset != 0 && target_sym_size != 0 && target_sym_entsize != 0) {
                int num_syms = target_sym_size / target_sym_entsize;
                for (int i = 0; i < num_syms; i++) {
                    uint64_t sym_offset = target_sym_offset + i * target_sym_entsize;
                    if (sym_offset + sizeof(Elf64_Sym) > length) break;

                    Elf64_Sym *sym = reinterpret_cast<Elf64_Sym *>(elf_bytes + sym_offset);
                    unsigned char type = ELF64_ST_TYPE(sym->st_info);
                    unsigned char bind = ELF64_ST_BIND(sym->st_info);

                    if (type == STT_FUNC || type == STT_OBJECT) {
                        std::string name;
                        if (target_str_offset != 0 && sym->st_name < target_str_size) {
                            const char *sym_name = reinterpret_cast<const char *>(elf_bytes + target_str_offset + sym->st_name);
                            if (target_str_offset + sym->st_name < length) {
                                name = std::string(sym_name);
                            }
                        }
                        if (name.empty()) {
                            name = (type == STT_FUNC) ? "sub_" + to_hex_string(sym->st_value).substr(2) : "data_" + to_hex_string(sym->st_value).substr(2);
                        }

                        std::string bind_str = "GLOBAL";
                        if (bind == STB_LOCAL) bind_str = "LOCAL";
                        else if (bind == STB_WEAK) bind_str = "WEAK";

                        std::string type_str = (type == STT_FUNC) ? "FUNC" : "OBJECT";

                        parsed_symbols.push_back({
                            to_hex_string(sym->st_value),
                            simple_demangle(name),
                            std::to_string(sym->st_size) + " bytes",
                            bind_str,
                            type_str,
                            i
                        });
                    }
                }
            }
        }
    } else if (elf_class == 1) {
        if (length >= sizeof(Elf32_Ehdr)) {
            Elf32_Ehdr *ehdr = reinterpret_cast<Elf32_Ehdr *>(elf_bytes);
            Elf32_Shdr *shdr = reinterpret_cast<Elf32_Shdr *>(elf_bytes + ehdr->e_shoff);

            uint32_t symtab_offset = 0;
            uint32_t symtab_size = 0;
            uint32_t symtab_entsize = 0;
            uint32_t strtab_offset = 0;
            uint32_t strtab_size = 0;

            uint32_t dynsym_offset = 0;
            uint32_t dynsym_size = 0;
            uint32_t dynsym_entsize = 0;
            uint32_t dynstr_offset = 0;
            uint32_t dynstr_size = 0;

            for (int i = 0; i < ehdr->e_shnum; i++) {
                uint32_t sh_offset = ehdr->e_shoff + i * ehdr->e_shentsize;
                if (sh_offset + sizeof(Elf32_Shdr) > length) break;

                Elf32_Shdr *sec = reinterpret_cast<Elf32_Shdr *>(elf_bytes + sh_offset);
                if (sec->sh_type == SHT_SYMTAB) {
                    symtab_offset = sec->sh_offset;
                    symtab_size = sec->sh_size;
                    symtab_entsize = sec->sh_entsize;
                } else if (sec->sh_type == SHT_STRTAB && i != ehdr->e_shstrndx) {
                    strtab_offset = sec->sh_offset;
                    strtab_size = sec->sh_size;
                } else if (sec->sh_type == SHT_DYNSYM) {
                    dynsym_offset = sec->sh_offset;
                    dynsym_size = sec->sh_size;
                    dynsym_entsize = sec->sh_entsize;
                }
            }

            for (int i = 0; i < ehdr->e_shnum; i++) {
                uint32_t sh_offset = ehdr->e_shoff + i * ehdr->e_shentsize;
                if (sh_offset + sizeof(Elf32_Shdr) > length) break;
                Elf32_Shdr *sec = reinterpret_cast<Elf32_Shdr *>(elf_bytes + sh_offset);
                if (sec->sh_type == SHT_STRTAB && i != ehdr->e_shstrndx && sec->sh_offset != strtab_offset) {
                    dynstr_offset = sec->sh_offset;
                    dynstr_size = sec->sh_size;
                }
            }

            uint32_t target_sym_offset = (symtab_offset != 0) ? symtab_offset : dynsym_offset;
            uint32_t target_sym_size = (symtab_offset != 0) ? symtab_size : dynsym_size;
            uint32_t target_sym_entsize = (symtab_offset != 0) ? symtab_entsize : dynsym_entsize;
            uint32_t target_str_offset = (symtab_offset != 0) ? strtab_offset : dynstr_offset;
            uint32_t target_str_size = (symtab_offset != 0) ? strtab_size : dynstr_size;

            if (target_sym_offset != 0 && target_sym_size != 0 && target_sym_entsize != 0) {
                int num_syms = target_sym_size / target_sym_entsize;
                for (int i = 0; i < num_syms; i++) {
                    uint32_t sym_offset = target_sym_offset + i * target_sym_entsize;
                    if (sym_offset + sizeof(Elf32_Sym) > length) break;

                    Elf32_Sym *sym = reinterpret_cast<Elf32_Sym *>(elf_bytes + sym_offset);
                    unsigned char type = ELF32_ST_TYPE(sym->st_info);
                    unsigned char bind = ELF32_ST_BIND(sym->st_info);

                    if (type == STT_FUNC || type == STT_OBJECT) {
                        std::string name;
                        if (target_str_offset != 0 && sym->st_name < target_str_size) {
                            const char *sym_name = reinterpret_cast<const char *>(elf_bytes + target_str_offset + sym->st_name);
                            if (target_str_offset + sym->st_name < length) {
                                name = std::string(sym_name);
                            }
                        }
                        if (name.empty()) {
                            name = (type == STT_FUNC) ? "sub_" + to_hex_string(sym->st_value).substr(2) : "data_" + to_hex_string(sym->st_value).substr(2);
                        }

                        std::string bind_str = "GLOBAL";
                        if (bind == STB_LOCAL) bind_str = "LOCAL";
                        else if (bind == STB_WEAK) bind_str = "WEAK";

                        std::string type_str = (type == STT_FUNC) ? "FUNC" : "OBJECT";

                        parsed_symbols.push_back({
                            to_hex_string(sym->st_value),
                            simple_demangle(name),
                            std::to_string(sym->st_size) + " bytes",
                            bind_str,
                            type_str,
                            i
                        });
                    }
                }
            }
        }
    }

    munmap(addr, length);

    for (const auto& sym : parsed_symbols) {
        jstring address_jstr = env->NewStringUTF(sym.address.c_str());
        jstring name_jstr = env->NewStringUTF(sym.name.c_str());
        jstring size_jstr = env->NewStringUTF(sym.size.c_str());
        jstring bind_jstr = env->NewStringUTF(sym.bind.c_str());
        jstring type_jstr = env->NewStringUTF(sym.type.c_str());

        jobject func_obj = env->NewObject(
            func_class, 
            func_init, 
            address_jstr, 
            name_jstr, 
            size_jstr, 
            bind_jstr, 
            type_jstr, 
            sym.index
        );

        env->CallBooleanMethod(list_obj, list_add, func_obj);

        env->DeleteLocalRef(address_jstr);
        env->DeleteLocalRef(name_jstr);
        env->DeleteLocalRef(size_jstr);
        env->DeleteLocalRef(bind_jstr);
        env->DeleteLocalRef(type_jstr);
        env->DeleteLocalRef(func_obj);
    }

    return list_obj;
}

JNIEXPORT jobjectArray JNICALL
Java_com_example_ElfParser_disassembleNative(JNIEnv *env, jobject thiz, jbyteArray buffer, jlong base_address, jlong length) {
    if (!buffer) return nullptr;
    jsize len = env->GetArrayLength(buffer);
    if (length < len) len = length;

    jbyte* bytes = env->GetByteArrayElements(buffer, nullptr);
    if (!bytes) return nullptr;

    csh handle;
    std::vector<std::string> results;

    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) == 0) {
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        cs_insn *insn = nullptr;
        size_t count = cs_disasm(handle, reinterpret_cast<const uint8_t*>(bytes), len, base_address, 0, &insn);
        if (count > 0) {
            results.reserve(count);
            for (size_t i = 0; i < count; ++i) {
                std::stringstream ss;
                ss << "[" << to_hex_string(insn[i].address) << "] ";
                ss << "[";
                for (int b = 0; b < insn[i].size; ++b) {
                    ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)insn[i].bytes[b];
                }
                ss << "] ";
                ss << insn[i].mnemonic << " " << insn[i].op_str;
                results.push_back(ss.str());
            }
            cs_free(insn, count);
        }
        cs_close(&handle);
    }

    env->ReleaseByteArrayElements(buffer, bytes, JNI_ABORT);

    jclass string_class = env->FindClass("java/lang/String");
    jobjectArray array = env->NewObjectArray(results.size(), string_class, nullptr);
    for (size_t i = 0; i < results.size(); ++i) {
        jstring js = env->NewStringUTF(results[i].c_str());
        env->SetObjectArrayElement(array, i, js);
        env->DeleteLocalRef(js);
    }
    return array;
}

extern "C++" std::string decompile_instructions_to_c(
    const cs_insn *insns, 
    size_t count, 
    const std::string& func_name,
    const std::unordered_map<uint64_t, std::string>& global_strings
);

JNIEXPORT jstring JNICALL
Java_com_example_ElfParser_decompileNative(JNIEnv *env, jobject thiz, jbyteArray buffer, jlong base_address, jlong length) {
    if (!buffer) return nullptr;
    jsize len = env->GetArrayLength(buffer);
    if (length < len) len = length;

    jbyte* bytes = env->GetByteArrayElements(buffer, nullptr);
    if (!bytes) return nullptr;

    csh handle;
    std::string decompiled_str = "";

    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) == 0) {
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        cs_insn *insn = nullptr;
        size_t count = cs_disasm(handle, reinterpret_cast<const uint8_t*>(bytes), len, base_address, 0, &insn);
        if (count > 0) {
            std::unordered_map<uint64_t, std::string> empty_globals;
            decompiled_str = decompile_instructions_to_c(insn, count, "interactive_func", empty_globals);
            cs_free(insn, count);
        }
        cs_close(&handle);
    }

    env->ReleaseByteArrayElements(buffer, bytes, JNI_ABORT);
    return env->NewStringUTF(decompiled_str.c_str());
}

JNIEXPORT jobjectArray JNICALL
Java_com_example_ElfParser_disassembleSection(JNIEnv *env, jobject thiz, jbyteArray code_array, jlong base_address, jint elf_machine_type, jboolean is_64_bit) {
    if (!code_array) return nullptr;
    jsize len = env->GetArrayLength(code_array);
    if (len == 0) return nullptr;

    jbyte* bytes = env->GetByteArrayElements(code_array, nullptr);
    if (!bytes) return nullptr;

    csh handle;
    cs_arch arch = CS_ARCH_ARM64;
    cs_mode mode = CS_MODE_ARM;

    // Determine architecture and mode based on ELF e_machine
    switch (elf_machine_type) {
        case 3: // EM_386
            arch = CS_ARCH_X86;
            mode = CS_MODE_32;
            break;
        case 62: // EM_X86_64
            arch = CS_ARCH_X86;
            mode = CS_MODE_64;
            break;
        case 40: // EM_ARM
            arch = CS_ARCH_ARM;
            mode = CS_MODE_ARM;
            break;
        case 183: // EM_AARCH64
            arch = CS_ARCH_ARM64;
            mode = CS_MODE_ARM; // ARM64 uses CS_MODE_ARM (0)
            break;
        default:
            // Fallback default
            arch = is_64_bit ? CS_ARCH_ARM64 : CS_ARCH_ARM;
            mode = CS_MODE_ARM;
            break;
    }

    jobjectArray array = nullptr;

    try {
        if (cs_open(arch, mode, &handle) == CS_ERR_OK) {
            cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
            cs_insn *insn = nullptr;
            size_t count = cs_disasm(handle, reinterpret_cast<const uint8_t*>(bytes), len, base_address, 0, &insn);
            
            jclass line_class = env->FindClass("com/example/DisassemblyLine");
            if (line_class) {
                jmethodID constructor = env->GetMethodID(line_class, "<init>", "(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
                
                if (count > 0 && constructor) {
                    array = env->NewObjectArray(count, line_class, nullptr);
                    for (size_t i = 0; i < count; ++i) {
                        // Create bytes hex string
                        std::stringstream ss;
                        for (int b = 0; b < insn[i].size; ++b) {
                            ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)insn[i].bytes[b];
                        }
                        std::string hex_str = ss.str();

                        jstring j_hex = env->NewStringUTF(hex_str.c_str());
                        jstring j_mnemonic = env->NewStringUTF(insn[i].mnemonic);
                        jstring j_op_str = env->NewStringUTF(insn[i].op_str);

                        jobject line_obj = env->NewObject(line_class, constructor, (jlong)insn[i].address, j_hex, j_mnemonic, j_op_str);

                        env->SetObjectArrayElement(array, i, line_obj);

                        env->DeleteLocalRef(j_hex);
                        env->DeleteLocalRef(j_mnemonic);
                        env->DeleteLocalRef(j_op_str);
                        env->DeleteLocalRef(line_obj);
                    }
                } else {
                    // Fallback empty array instead of null to prevent NPE
                    array = env->NewObjectArray(0, line_class, nullptr);
                }
                if (insn) {
                    cs_free(insn, count);
                }
            }
            cs_close(&handle);
        }
    } catch (...) {
        // Safe isolation, ignore and ensure no crash
    }

    env->ReleaseByteArrayElements(code_array, bytes, JNI_ABORT);
    return array;
}

// Advanced custom pseudocode translator mapping assembly logic directly to C constructs
extern "C++" std::string decompile_instructions_to_c(
    const cs_insn *insns, 
    size_t count, 
    const std::string& func_name,
    const std::unordered_map<uint64_t, std::string>& global_strings
) {
    std::stringstream ps;
    ps << "\n// Virtual Address: " << to_hex_string(insns[0].address) << "\n";
    ps << "// Demangled: " << func_name << "\n";
    ps << "int " << sanitize_function_name(func_name) << "(";
    
    // Standard signature with mock generic parameters
    ps << "long a1, long a2, long a3, long a4) {\n";
    ps << "    // Local variables mapping registers\n";
    ps << "    _QWORD v0 = 0, v1 = 0, v2 = 0, v3 = 0, v4 = 0, v5 = 0;\n";
    ps << "    _DWORD d0 = 0, d1 = 0, d2 = 0, d3 = 0;\n";
    ps << "    void* ptr = nullptr;\n\n";

    std::string current_cmp_reg = "";
    std::string current_cmp_val = "";
    bool has_cmp = false;

    // Local registers map to track relative page base loads (like ADRP)
    std::unordered_map<std::string, uint64_t> reg_values;

    auto parse_imm = [](const std::string& op_str) -> uint64_t {
        size_t hash = op_str.find('#');
        if (hash == std::string::npos) return 0;
        std::string val_str = op_str.substr(hash + 1);
        while (!val_str.empty() && (val_str.back() == ']' || val_str.back() == ' ' || val_str.back() == ')')) {
            val_str.pop_back();
        }
        try {
            if (val_str.rfind("0x", 0) == 0 || val_str.rfind("0X", 0) == 0) {
                return std::stoull(val_str, nullptr, 16);
            } else {
                return std::stoull(val_str, nullptr, 10);
            }
        } catch (...) {
            return 0;
        }
    };

    for (size_t i = 0; i < count; ++i) {
        const cs_insn &insn = insns[i];
        std::string mnemonic = insn.mnemonic;
        std::string op_str = insn.op_str;

        ps << "    // " << mnemonic << " " << op_str << "\n";

        if (mnemonic == "cmp") {
            size_t comma = op_str.find(',');
            if (comma != std::string::npos) {
                current_cmp_reg = op_str.substr(0, comma);
                size_t hash = op_str.find('#', comma);
                if (hash != std::string::npos) {
                    current_cmp_val = op_str.substr(hash + 1);
                } else {
                    current_cmp_val = op_str.substr(comma + 2);
                }
                has_cmp = true;
            }
        } 
        else if (mnemonic == "adrp") {
            size_t comma = op_str.find(',');
            if (comma != std::string::npos) {
                std::string reg = op_str.substr(0, comma);
                uint64_t imm = parse_imm(op_str.substr(comma + 1));
                reg_values[reg] = imm;
                ps << "    " << reg << " = " << to_hex_string(imm) << "; // Page base\n";
            }
        }
        else if (mnemonic.rfind("b.", 0) == 0) {
            std::string cond = mnemonic.substr(2);
            std::string label = op_str;
            if (has_cmp) {
                std::string op = "==";
                if (cond == "ne") op = "!=";
                else if (cond == "lt") op = "<";
                else if (cond == "le") op = "<=";
                else if (cond == "gt") op = ">";
                else if (cond == "ge") op = ">=";

                ps << "    if (" << current_cmp_reg << " " << op << " " << current_cmp_val << ") {\n";
                ps << "        goto loc_" << label << ";\n";
                ps << "    }\n";
            } else {
                ps << "    if (" << cond << ") {\n";
                ps << "        goto loc_" << label << ";\n";
                ps << "    }\n";
            }
        }
        else if (mnemonic == "b") {
            ps << "    goto loc_" << op_str << ";\n";
        }
        else if (mnemonic == "bl") {
            ps << "    " << sanitize_function_name("sub_" + op_str) << "(v0, v1, v2, v3);\n";
        }
        else if (mnemonic == "mov") {
            size_t comma = op_str.find(',');
            if (comma != std::string::npos) {
                std::string dest = op_str.substr(0, comma);
                std::string src = op_str.substr(comma + 2);
                if (dest[0] == 'w') {
                    ps << "    d" << dest.substr(1) << " = " << src << ";\n";
                } else if (dest[0] == 'x') {
                    ps << "    v" << dest.substr(1) << " = " << src << ";\n";
                } else {
                    ps << "    " << dest << " = " << src << ";\n";
                }
            }
        }
        else if (mnemonic == "add" || mnemonic == "sub") {
            size_t first_comma = op_str.find(',');
            if (first_comma != std::string::npos) {
                std::string rd = op_str.substr(0, first_comma);
                size_t second_comma = op_str.find(',', first_comma + 1);
                if (second_comma != std::string::npos) {
                    std::string rn = op_str.substr(first_comma + 2, second_comma - (first_comma + 2));
                    uint64_t imm = parse_imm(op_str.substr(second_comma + 2));
                    char op = (mnemonic == "add") ? '+' : '-';
                    
                    if (reg_values.count(rn) > 0) {
                        uint64_t base = reg_values[rn];
                        uint64_t addr = (mnemonic == "add") ? (base + imm) : (base - imm);
                        reg_values[rd] = addr;
                        if (global_strings.count(addr) > 0) {
                            ps << "    " << rd << " = &str_" << std::uppercase << std::hex << addr << "; // " << global_strings.at(addr) << "\n";
                        } else {
                            ps << "    " << rd << " = " << to_hex_string(addr) << ";\n";
                        }
                    } else {
                        ps << "    " << rd << " = " << rn << " " << op << " " << imm << ";\n";
                    }
                } else {
                    std::string src = op_str.substr(first_comma + 2);
                    char op = (mnemonic == "add") ? '+' : '-';
                    ps << "    " << rd << " = " << rd << " " << op << " " << src << ";\n";
                }
            }
        }
        else if (mnemonic == "ldr") {
            size_t first_comma = op_str.find(',');
            if (first_comma != std::string::npos) {
                std::string rd = op_str.substr(0, first_comma);
                std::string mem = op_str.substr(first_comma + 2);
                
                size_t lbracket = mem.find('[');
                size_t rbracket = mem.find(']');
                if (lbracket != std::string::npos && rbracket != std::string::npos) {
                    std::string inner = mem.substr(lbracket + 1, rbracket - lbracket - 1);
                    size_t comma = inner.find(',');
                    if (comma != std::string::npos) {
                        std::string rn = inner.substr(0, comma);
                        uint64_t imm = parse_imm(inner.substr(comma + 1));
                        if (reg_values.count(rn) > 0) {
                            uint64_t addr = reg_values[rn] + imm;
                            reg_values[rd] = addr;
                            if (global_strings.count(addr) > 0) {
                                ps << "    " << rd << " = str_" << std::uppercase << std::hex << addr << "; // " << global_strings.at(addr) << "\n";
                            } else {
                                ps << "    " << rd << " = *(_QWORD *)(" << to_hex_string(addr) << ");\n";
                            }
                        } else {
                            ps << "    " << rd << " = *(_QWORD *)(" << rn << " + " << imm << ");\n";
                        }
                    } else {
                        std::string rn = inner;
                        if (reg_values.count(rn) > 0) {
                            uint64_t addr = reg_values[rn];
                            reg_values[rd] = addr;
                            if (global_strings.count(addr) > 0) {
                                ps << "    " << rd << " = str_" << std::uppercase << std::hex << addr << "; // " << global_strings.at(addr) << "\n";
                            } else {
                                ps << "    " << rd << " = *(_QWORD *)(" << to_hex_string(addr) << ");\n";
                            }
                        } else {
                            ps << "    " << rd << " = *(_QWORD *)(" << rn << ");\n";
                        }
                    }
                } else {
                    ps << "    " << rd << " = *" << mem << ";\n";
                }
            }
        }
        else if (mnemonic == "str") {
            size_t first_comma = op_str.find(',');
            if (first_comma != std::string::npos) {
                std::string rd = op_str.substr(0, first_comma);
                std::string mem = op_str.substr(first_comma + 2);
                ps << "    *(_DWORD *)(" << mem << ") = " << rd << ";\n";
            }
        }
        else if (mnemonic == "ret") {
            ps << "    return v0;\n";
        }
    }

    ps << "}\n";
    return ps.str();
}

// High-performance JNI bridge that decompiles `.so` files chunk-by-chunk on disk safely
JNIEXPORT jboolean JNICALL
Java_com_example_ElfParser_decompileFileToCNative(JNIEnv *env, jobject thiz, jstring input_path, jstring output_path, jobject callback) {
    if (!input_path || !output_path || !callback) return JNI_FALSE;

    const char *in_path = env->GetStringUTFChars(input_path, nullptr);
    const char *out_path = env->GetStringUTFChars(output_path, nullptr);

    if (!in_path || !out_path) {
        if (in_path) env->ReleaseStringUTFChars(input_path, in_path);
        if (out_path) env->ReleaseStringUTFChars(output_path, out_path);
        return JNI_FALSE;
    }

    // Lookup callback onProgress method ID
    jclass cbClass = env->GetObjectClass(callback);
    jmethodID onProgressMethod = env->GetMethodID(cbClass, "onProgress", "(JJILjava/lang/String;)V");
    if (!onProgressMethod) {
        env->ReleaseStringUTFChars(input_path, in_path);
        env->ReleaseStringUTFChars(output_path, out_path);
        return JNI_FALSE;
    }

    // Open file streams directly on disk (no massive mapping or memory usage)
    std::ifstream inFile(in_path, std::ios::binary);
    std::ofstream outFile(out_path);

    if (!inFile.is_open() || !outFile.is_open()) {
        if (in_path) env->ReleaseStringUTFChars(input_path, in_path);
        if (out_path) env->ReleaseStringUTFChars(output_path, out_path);
        return JNI_FALSE;
    }

    // Read total file size
    inFile.seekg(0, std::ios::end);
    long long totalBytes = inFile.tellg();
    inFile.seekg(0, std::ios::beg);

    if (totalBytes < sizeof(Elf32_Ehdr)) {
        inFile.close();
        outFile.close();
        env->ReleaseStringUTFChars(input_path, in_path);
        env->ReleaseStringUTFChars(output_path, out_path);
        return JNI_FALSE;
    }

    // Verify ELF identity
    unsigned char elf_ident[16];
    inFile.read(reinterpret_cast<char*>(elf_ident), 16);
    if (elf_ident[0] != 0x7F || elf_ident[1] != 'E' || elf_ident[2] != 'L' || elf_ident[3] != 'F') {
        inFile.close();
        outFile.close();
        env->ReleaseStringUTFChars(input_path, in_path);
        env->ReleaseStringUTFChars(output_path, out_path);
        return JNI_FALSE;
    }

    bool is64Bit = (elf_ident[4] == 2);
    bool isLittleEndian = (elf_ident[5] == 1);

    struct DecompileFuncInfo {
        std::string name;
        uint64_t virtualAddress;
        uint64_t fileOffset;
        uint64_t size;
    };
    std::vector<DecompileFuncInfo> targetFuncs;

    // Read machine architecture type
    int elf_machine_type = 183;
    inFile.seekg(18, std::ios::beg);
    uint16_t e_machine = 0;
    inFile.read(reinterpret_cast<char*>(&e_machine), 2);
    elf_machine_type = e_machine;

    uint64_t shoff = 0;
    uint16_t shentsize = 0;
    uint16_t shnum = 0;
    uint16_t shstrndx = 0;

    if (is64Bit) {
        inFile.seekg(40, std::ios::beg);
        inFile.read(reinterpret_cast<char*>(&shoff), 8);
        inFile.seekg(58, std::ios::beg);
        inFile.read(reinterpret_cast<char*>(&shentsize), 2);
        inFile.read(reinterpret_cast<char*>(&shnum), 2);
        inFile.read(reinterpret_cast<char*>(&shstrndx), 2);
    } else {
        uint32_t shoff32 = 0;
        inFile.seekg(32, std::ios::beg);
        inFile.read(reinterpret_cast<char*>(&shoff32), 4);
        shoff = shoff32;
        inFile.seekg(46, std::ios::beg);
        inFile.read(reinterpret_cast<char*>(&shentsize), 2);
        inFile.read(reinterpret_cast<char*>(&shnum), 2);
        inFile.read(reinterpret_cast<char*>(&shstrndx), 2);
    }

    uint64_t symtabOffset = 0;
    uint64_t symtabSize = 0;
    uint64_t symtabEntSize = 0;
    uint64_t strtabOffset = 0;
    uint64_t strtabSize = 0;

    uint64_t dynsymOffset = 0;
    uint64_t dynsymSize = 0;
    uint64_t dynsymEntSize = 0;
    uint64_t dynstrOffset = 0;
    uint64_t dynstrSize = 0;

    // Scan Section Headers for symbol maps
    for (int i = 0; i < shnum; i++) {
        uint64_t secOffset = shoff + i * shentsize;
        if (secOffset + shentsize > totalBytes) break;

        inFile.seekg(secOffset, std::ios::beg);
        uint32_t sh_name = 0;
        inFile.read(reinterpret_cast<char*>(&sh_name), 4);

        uint32_t sh_type = 0;
        inFile.read(reinterpret_cast<char*>(&sh_type), 4);

        uint64_t sh_addr = 0;
        uint64_t sh_offset = 0;
        uint64_t sh_size = 0;
        uint64_t sh_entsize = 0;

        if (is64Bit) {
            inFile.seekg(secOffset + 16, std::ios::beg);
            inFile.read(reinterpret_cast<char*>(&sh_addr), 8);
            inFile.read(reinterpret_cast<char*>(&sh_offset), 8);
            inFile.read(reinterpret_cast<char*>(&sh_size), 8);
            inFile.seekg(secOffset + 56, std::ios::beg);
            inFile.read(reinterpret_cast<char*>(&sh_entsize), 8);
        } else {
            uint32_t tmp_addr = 0, tmp_offset = 0, tmp_size = 0, tmp_entsize = 0;
            inFile.seekg(secOffset + 12, std::ios::beg);
            inFile.read(reinterpret_cast<char*>(&tmp_addr), 4);
            inFile.read(reinterpret_cast<char*>(&tmp_offset), 4);
            inFile.read(reinterpret_cast<char*>(&tmp_size), 4);
            inFile.seekg(secOffset + 36, std::ios::beg);
            inFile.read(reinterpret_cast<char*>(&tmp_entsize), 4);
            sh_addr = tmp_addr;
            sh_offset = tmp_offset;
            sh_size = tmp_size;
            sh_entsize = tmp_entsize;
        }

        if (sh_type == SHT_SYMTAB) {
            symtabOffset = sh_offset;
            symtabSize = sh_size;
            symtabEntSize = sh_entsize;
        } else if (sh_type == SHT_DYNSYM) {
            dynsymOffset = sh_offset;
            dynsymSize = sh_size;
            dynsymEntSize = sh_entsize;
        } else if (sh_type == SHT_STRTAB) {
            if (i != shstrndx) {
                if (strtabOffset == 0) {
                    strtabOffset = sh_offset;
                    strtabSize = sh_size;
                } else {
                    dynstrOffset = sh_offset;
                    dynstrSize = sh_size;
                }
            }
        }
    }

    uint64_t targetSymOffset = (symtabOffset != 0) ? symtabOffset : dynsymOffset;
    uint64_t targetSymSize = (symtabOffset != 0) ? symtabSize : dynsymSize;
    uint64_t targetSymEntSize = (symtabOffset != 0) ? symtabEntSize : dynsymEntSize;
    uint64_t targetStrOffset = (symtabOffset != 0) ? strtabOffset : (dynstrOffset != 0 ? dynstrOffset : strtabOffset);
    uint64_t targetStrSize = (symtabOffset != 0) ? strtabSize : (dynstrOffset != 0 ? dynstrSize : strtabSize);

    // Read symbols from file stream sequentially
    if (targetSymOffset != 0 && targetSymSize != 0 && targetSymEntSize != 0) {
        int count = targetSymSize / targetSymEntSize;
        for (int i = 0; i < count; i++) {
            uint64_t entryOffset = targetSymOffset + i * targetSymEntSize;
            if (entryOffset + targetSymEntSize > totalBytes) break;

            inFile.seekg(entryOffset, std::ios::beg);
            uint32_t st_name = 0;
            inFile.read(reinterpret_cast<char*>(&st_name), 4);

            unsigned char st_info = 0;
            uint64_t st_value = 0;
            uint64_t st_size = 0;

            if (is64Bit) {
                inFile.seekg(entryOffset + 4, std::ios::beg);
                inFile.read(reinterpret_cast<char*>(&st_info), 1);
                inFile.seekg(entryOffset + 8, std::ios::beg);
                inFile.read(reinterpret_cast<char*>(&st_value), 8);
                inFile.read(reinterpret_cast<char*>(&st_size), 8);
            } else {
                uint32_t tmp_val = 0, tmp_size = 0;
                inFile.seekg(entryOffset + 4, std::ios::beg);
                inFile.read(reinterpret_cast<char*>(&tmp_val), 4);
                inFile.read(reinterpret_cast<char*>(&tmp_size), 4);
                inFile.seekg(entryOffset + 12, std::ios::beg);
                inFile.read(reinterpret_cast<char*>(&st_info), 1);
                st_value = tmp_val;
                st_size = tmp_size;
            }

            unsigned char type = st_info & 0x0F;
            if (type == STT_FUNC && st_value > 0) {
                std::string name = "";
                uint64_t nameOffset = targetStrOffset + st_name;
                if (targetStrOffset != 0 && nameOffset < totalBytes) {
                    inFile.seekg(nameOffset, std::ios::beg);
                    char ch;
                    while (inFile.get(ch) && ch != '\0' && name.length() < 256) {
                        name += ch;
                    }
                }

                if (name.empty()) {
                    name = "sub_" + to_hex_string(st_value).substr(2);
                }

                // Translate virtual address to file offset using program headers (PT_LOAD)
                uint64_t fileOffset = st_value; 
                uint64_t phoff = 0;
                uint16_t phentsize = 0;
                uint16_t phnum = 0;
                if (is64Bit) {
                    inFile.seekg(32, std::ios::beg);
                    inFile.read(reinterpret_cast<char*>(&phoff), 8);
                    inFile.seekg(54, std::ios::beg);
                    inFile.read(reinterpret_cast<char*>(&phentsize), 2);
                    inFile.read(reinterpret_cast<char*>(&phnum), 2);
                } else {
                    uint32_t phoff32 = 0;
                    inFile.seekg(28, std::ios::beg);
                    inFile.read(reinterpret_cast<char*>(&phoff32), 4);
                    phoff = phoff32;
                    inFile.seekg(42, std::ios::beg);
                    inFile.read(reinterpret_cast<char*>(&phentsize), 2);
                    inFile.read(reinterpret_cast<char*>(&phnum), 2);
                }

                if (phoff > 0 && phnum > 0) {
                    for (int p = 0; p < phnum; p++) {
                        uint64_t phOffset = phoff + p * phentsize;
                        inFile.seekg(phOffset, std::ios::beg);
                        uint32_t p_type = 0;
                        inFile.read(reinterpret_cast<char*>(&p_type), 4);
                        if (p_type == 1) { // PT_LOAD
                            uint64_t p_offset = 0, p_vaddr = 0, p_memsz = 0;
                            if (is64Bit) {
                                inFile.seekg(phOffset + 8, std::ios::beg);
                                inFile.read(reinterpret_cast<char*>(&p_offset), 8);
                                inFile.read(reinterpret_cast<char*>(&p_vaddr), 8);
                                inFile.seekg(phOffset + 40, std::ios::beg);
                                inFile.read(reinterpret_cast<char*>(&p_memsz), 8);
                            } else {
                                uint32_t t_offset = 0, t_vaddr = 0, t_memsz = 0;
                                inFile.seekg(phOffset + 4, std::ios::beg);
                                inFile.read(reinterpret_cast<char*>(&t_offset), 4);
                                inFile.read(reinterpret_cast<char*>(&t_vaddr), 4);
                                inFile.seekg(phOffset + 20, std::ios::beg);
                                inFile.read(reinterpret_cast<char*>(&t_memsz), 4);
                                p_offset = t_offset;
                                p_vaddr = t_vaddr;
                                p_memsz = t_memsz;
                            }

                            if (st_value >= p_vaddr && st_value < p_vaddr + p_memsz) {
                                fileOffset = p_offset + (st_value - p_vaddr);
                                break;
                            }
                        }
                    }
                }

                if (fileOffset > 0 && fileOffset < totalBytes) {
                    targetFuncs.push_back({
                        simple_demangle(name),
                        st_value,
                        fileOffset,
                        st_size
                    });
                }
            }
        }
    }

    // Sort targetFuncs by virtual address
    std::sort(targetFuncs.begin(), targetFuncs.end(), [](const DecompileFuncInfo& a, const DecompileFuncInfo& b) {
        return a.virtualAddress < b.virtualAddress;
    });

    // Remove duplicates
    targetFuncs.erase(
        std::unique(targetFuncs.begin(), targetFuncs.end(), [](const DecompileFuncInfo& a, const DecompileFuncInfo& b) {
            return a.virtualAddress == b.virtualAddress;
        }),
        targetFuncs.end()
    );

    // Fill in sizes for functions with size == 0
    for (size_t i = 0; i < targetFuncs.size(); ++i) {
        if (targetFuncs[i].size == 0) {
            if (i + 1 < targetFuncs.size()) {
                uint64_t calculatedSize = targetFuncs[i + 1].virtualAddress - targetFuncs[i].virtualAddress;
                targetFuncs[i].size = std::min(calculatedSize, static_cast<uint64_t>(65536));
            } else {
                targetFuncs[i].size = 1024;
            }
        }
    }

    // Fallback: If stripped, scan executable segments for function entry points (prologues)
    if (targetFuncs.empty()) {
        uint64_t phoff = 0;
        uint16_t phentsize = 0;
        uint16_t phnum = 0;
        if (is64Bit) {
            inFile.seekg(32, std::ios::beg);
            inFile.read(reinterpret_cast<char*>(&phoff), 8);
            inFile.seekg(54, std::ios::beg);
            inFile.read(reinterpret_cast<char*>(&phentsize), 2);
            inFile.read(reinterpret_cast<char*>(&phnum), 2);
        } else {
            uint32_t phoff32 = 0;
            inFile.seekg(28, std::ios::beg);
            inFile.read(reinterpret_cast<char*>(&phoff32), 4);
            phoff = phoff32;
            inFile.seekg(42, std::ios::beg);
            inFile.read(reinterpret_cast<char*>(&phentsize), 2);
            inFile.read(reinterpret_cast<char*>(&phnum), 2);
        }

        if (phoff > 0 && phnum > 0) {
            for (int p = 0; p < phnum; p++) {
                uint64_t phOffset = phoff + p * phentsize;
                inFile.seekg(phOffset, std::ios::beg);
                uint32_t p_type = 0;
                inFile.read(reinterpret_cast<char*>(&p_type), 4);
                if (p_type == 1) { // PT_LOAD
                    uint32_t p_flags = 0;
                    if (is64Bit) {
                        inFile.seekg(phOffset + 4, std::ios::beg);
                        inFile.read(reinterpret_cast<char*>(&p_flags), 4);
                    } else {
                        inFile.seekg(phOffset + 24, std::ios::beg);
                        inFile.read(reinterpret_cast<char*>(&p_flags), 4);
                    }

                    if (p_flags & 1) { // Executable
                        uint64_t p_offset = 0, p_vaddr = 0, p_filesz = 0;
                        if (is64Bit) {
                            inFile.seekg(phOffset + 8, std::ios::beg);
                            inFile.read(reinterpret_cast<char*>(&p_offset), 8);
                            inFile.read(reinterpret_cast<char*>(&p_vaddr), 8);
                            inFile.seekg(phOffset + 32, std::ios::beg);
                            inFile.read(reinterpret_cast<char*>(&p_filesz), 8);
                        } else {
                            uint32_t t_offset = 0, t_vaddr = 0, t_filesz = 0;
                            inFile.seekg(phOffset + 4, std::ios::beg);
                            inFile.read(reinterpret_cast<char*>(&t_offset), 4);
                            inFile.read(reinterpret_cast<char*>(&t_vaddr), 4);
                            inFile.seekg(phOffset + 16, std::ios::beg);
                            inFile.read(reinterpret_cast<char*>(&t_filesz), 4);
                            p_offset = t_offset;
                            p_vaddr = t_vaddr;
                            p_filesz = t_filesz;
                        }

                        if (p_filesz > 0 && p_offset > 0 && p_offset < totalBytes) {
                            std::vector<uint8_t> execBytes(p_filesz);
                            std::streampos originalPos = inFile.tellg();
                            inFile.seekg(p_offset, std::ios::beg);
                            inFile.read(reinterpret_cast<char*>(execBytes.data()), p_filesz);
                            inFile.seekg(originalPos, std::ios::beg);

                            std::vector<uint64_t> entryPoints;
                            entryPoints.push_back(p_vaddr);

                            if (elf_machine_type == 183) { // EM_AARCH64
                                for (size_t offset = 0; offset + 4 <= p_filesz; offset += 4) {
                                    uint32_t instr = *reinterpret_cast<uint32_t*>(&execBytes[offset]);
                                    bool is_stp = (instr & 0xFFC0FFFF) == 0xA9007BFD || (instr & 0xFFC0FFFF) == 0xA9807BFD;
                                    bool is_sub_sp = (instr & 0xFFC003FF) == 0xD10003FF;
                                    if (is_stp || is_sub_sp) {
                                        uint64_t addr = p_vaddr + offset;
                                        if (addr != p_vaddr) {
                                            entryPoints.push_back(addr);
                                        }
                                    }
                                }
                            } else if (elf_machine_type == 40) { // EM_ARM
                                for (size_t offset = 0; offset + 4 <= p_filesz; offset += 4) {
                                    uint32_t instr = *reinterpret_cast<uint32_t*>(&execBytes[offset]);
                                    if ((instr & 0xFFFF4000) == 0xE92D4000) {
                                        entryPoints.push_back(p_vaddr + offset);
                                    }
                                }
                            } else if (elf_machine_type == 62 || elf_machine_type == 3) { // x86_64 or x86
                                for (size_t offset = 0; offset + 2 <= p_filesz; offset++) {
                                    if (execBytes[offset] == 0x55) {
                                        if (offset + 3 < p_filesz && execBytes[offset+1] == 0x48 && execBytes[offset+2] == 0x89 && execBytes[offset+3] == 0xE5) {
                                            entryPoints.push_back(p_vaddr + offset);
                                        } else if (offset + 2 < p_filesz && execBytes[offset+1] == 0x89 && execBytes[offset+2] == 0xE5) {
                                            entryPoints.push_back(p_vaddr + offset);
                                        }
                                    }
                                }
                            }

                            std::sort(entryPoints.begin(), entryPoints.end());
                            entryPoints.erase(std::unique(entryPoints.begin(), entryPoints.end()), entryPoints.end());

                            for (size_t i = 0; i < entryPoints.size(); ++i) {
                                uint64_t addr = entryPoints[i];
                                uint64_t size = 1024;
                                if (i + 1 < entryPoints.size()) {
                                    size = entryPoints[i+1] - addr;
                                } else {
                                    size = (p_vaddr + p_filesz) - addr;
                                }
                                size = std::min(size, static_cast<uint64_t>(65536));

                                targetFuncs.push_back({
                                    "sub_" + to_hex_string(addr).substr(2),
                                    addr,
                                    p_offset + (addr - p_vaddr),
                                    size
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    std::unordered_map<uint64_t, std::string> global_strings;
    std::vector<GlobalData> extracted_globals;

    auto local_getSectionName = [&](uint32_t sh_name, uint64_t shstrtabOffset, uint64_t shstrtabSize) -> std::string {
        if (shstrtabOffset == 0 || sh_name >= shstrtabSize) return "";
        std::streampos orig = inFile.tellg();
        inFile.seekg(shstrtabOffset + sh_name, std::ios::beg);
        std::string name = "";
        char ch;
        while (inFile.get(ch) && ch != '\0' && name.length() < 128) {
            name += ch;
        }
        inFile.seekg(orig, std::ios::beg);
        return name;
    };

    uint64_t local_shstrtabOffset = 0;
    uint64_t local_shstrtabSize = 0;
    if (shstrndx < shnum) {
        uint64_t shstrSecOffset = shoff + shstrndx * shentsize;
        if (shstrSecOffset + shentsize <= totalBytes) {
            std::streampos orig = inFile.tellg();
            if (is64Bit) {
                inFile.seekg(shstrSecOffset + 24, std::ios::beg);
                inFile.read(reinterpret_cast<char*>(&local_shstrtabOffset), 8);
                inFile.read(reinterpret_cast<char*>(&local_shstrtabSize), 8);
            } else {
                uint32_t offset32 = 0, size32 = 0;
                inFile.seekg(shstrSecOffset + 16, std::ios::beg);
                inFile.read(reinterpret_cast<char*>(&offset32), 4);
                inFile.read(reinterpret_cast<char*>(&size32), 4);
                local_shstrtabOffset = offset32;
                local_shstrtabSize = size32;
            }
            inFile.seekg(orig, std::ios::beg);
        }
    }

    for (int i = 0; i < shnum; i++) {
        uint64_t secOffset = shoff + i * shentsize;
        if (secOffset + shentsize > totalBytes) break;

        std::streampos orig = inFile.tellg();
        inFile.seekg(secOffset, std::ios::beg);
        uint32_t sh_name = 0;
        inFile.read(reinterpret_cast<char*>(&sh_name), 4);
        std::string secName = local_getSectionName(sh_name, local_shstrtabOffset, local_shstrtabSize);

        uint32_t sh_type = 0;
        inFile.read(reinterpret_cast<char*>(&sh_type), 4);

        uint64_t sh_addr = 0, sh_offset = 0, sh_size = 0;
        if (is64Bit) {
            inFile.seekg(secOffset + 16, std::ios::beg);
            inFile.read(reinterpret_cast<char*>(&sh_addr), 8);
            inFile.read(reinterpret_cast<char*>(&sh_offset), 8);
            inFile.read(reinterpret_cast<char*>(&sh_size), 8);
        } else {
            uint32_t tmp_addr = 0, tmp_offset = 0, tmp_size = 0;
            inFile.seekg(secOffset + 12, std::ios::beg);
            inFile.read(reinterpret_cast<char*>(&tmp_addr), 4);
            inFile.read(reinterpret_cast<char*>(&tmp_offset), 4);
            inFile.read(reinterpret_cast<char*>(&tmp_size), 4);
            sh_addr = tmp_addr;
            sh_offset = tmp_offset;
            sh_size = tmp_size;
        }
        inFile.seekg(orig, std::ios::beg);

        if (secName == ".rodata" || secName == ".data" || secName == ".string") {
            auto dataList = extract_strings_and_data(inFile, sh_offset, sh_size, sh_addr, secName);
            for (const auto& gd : dataList) {
                global_strings[gd.virtualAddress] = gd.value;
                extracted_globals.push_back(gd);
            }
        }
    }

    // Write header to .c file
    outFile << "/*\n";
    outFile << " * Comprehensive C Pseudocode Dump - Generated by Mini IDA Pro\n";
    outFile << " * Input Binary: " << in_path << "\n";
    outFile << " * Total Size: " << totalBytes << " bytes\n";
    outFile << " * Format: " << (is64Bit ? "ELF64" : "ELF32") << ", " << (isLittleEndian ? "Little Endian" : "Big Endian") << "\n";
    outFile << " * Machine Type: " << elf_machine_type << "\n";
    outFile << " */\n\n";

    outFile << "#include <stdint.h>\n";
    outFile << "#include <stdbool.h>\n\n";

    outFile << "typedef uint8_t _BYTE;\n";
    outFile << "typedef uint16_t _WORD;\n";
    outFile << "typedef uint32_t _DWORD;\n";
    outFile << "typedef uint64_t _QWORD;\n\n";

    outFile << "// String Literals & Global Constants extracted from read-only data\n";
    for (const auto& gd : extracted_globals) {
        outFile << gd.type << " " << gd.name << "[] = " << gd.value << ";\n";
    }
    outFile << "\n\n";

    // Setup Capstone Disassembler
    csh handle;
    cs_arch arch = CS_ARCH_ARM64;
    cs_mode mode = CS_MODE_ARM;

    switch (elf_machine_type) {
        case 3:
            arch = CS_ARCH_X86;
            mode = CS_MODE_32;
            break;
        case 62:
            arch = CS_ARCH_X86;
            mode = CS_MODE_64;
            break;
        case 40:
            arch = CS_ARCH_ARM;
            mode = CS_MODE_ARM;
            break;
        case 183:
            arch = CS_ARCH_ARM64;
            mode = CS_MODE_ARM;
            break;
        default:
            arch = is64Bit ? CS_ARCH_ARM64 : CS_ARCH_ARM;
            mode = CS_MODE_ARM;
            break;
    }

    bool capstoneAvailable = (cs_open(arch, mode, &handle) == CS_ERR_OK);
    if (capstoneAvailable) {
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    }

    size_t numFuncs = targetFuncs.size();

    // Stream and process function-by-function to prevent any OOM build-ups
    for (size_t i = 0; i < numFuncs; ++i) {
        const auto& func = targetFuncs[i];

        std::vector<uint8_t> funcBytes(func.size);
        inFile.seekg(func.fileOffset, std::ios::beg);
        inFile.read(reinterpret_cast<char*>(funcBytes.data()), func.size);

        std::string pseudocode = "";
        if (capstoneAvailable && func.size > 0) {
            cs_insn *insns = nullptr;
            size_t count = cs_disasm(handle, funcBytes.data(), func.size, func.virtualAddress, 0, &insns);
            if (count > 0) {
                pseudocode = decompile_instructions_to_c(insns, count, func.name, global_strings);
                cs_free(insns, count);
            } else {
                pseudocode = "\n// Address: " + to_hex_string(func.virtualAddress) + "\n";
                pseudocode += "void " + func.name + "() {\n    // [Assembly interpretation failed]\n}\n";
            }
        } else {
            pseudocode = "\n// Address: " + to_hex_string(func.virtualAddress) + "\n";
            pseudocode += "void " + func.name + "() {\n    // [Capstone disassembler engine offline]\n}\n";
        }

        // Write directly to file on disk and flush stream immediately to clear buffer
        outFile << pseudocode;
        outFile.flush();

        // Update progress callback
        long long currentPos = inFile.tellg();
        int percentage = (int)((i + 1) * 100 / numFuncs);

        jstring jCurrentFunc = env->NewStringUTF(func.name.c_str());
        env->CallVoidMethod(callback, onProgressMethod, (jlong)currentPos, (jlong)totalBytes, (jint)percentage, jCurrentFunc);
        env->DeleteLocalRef(jCurrentFunc);
    }

    if (capstoneAvailable) {
        cs_close(&handle);
    }

    inFile.close();
    outFile.close();

    env->ReleaseStringUTFChars(input_path, in_path);
    env->ReleaseStringUTFChars(output_path, out_path);

    return JNI_TRUE;
}

}

