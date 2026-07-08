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
            decompiled_str = decompile_instructions(insn, count);
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

}
