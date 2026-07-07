package com.example

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.RecyclerView
import androidx.viewpager2.widget.ViewPager2
import com.google.android.material.button.MaterialButton
import com.google.android.material.tabs.TabLayout
import com.google.android.material.tabs.TabLayoutMediator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.ByteBuffer

class MainActivity : AppCompatActivity() {

    // Common/Cached state to prevent redundant parses & disk I/O
    private var binaryBuffer: ByteBuffer? = null
    private lateinit var offsetsDbHelper: OffsetsDatabaseHelper
    private var currentFileName: String = ""
    private var elfHeaderCached: ElfParser.ElfHeader? = null
    private var lastSelectedFunction: ElfParser.ElfFunction? = null
    
    private var allFunctionsCached: List<ElfParser.ElfFunction> = emptyList()
    private var allStringsCached: List<ElfParser.ElfString> = emptyList()
    private var allHexCached: List<ElfParser.HexRow> = emptyList()

    // Adapters
    private lateinit var functionsAdapter: FunctionsAdapter
    private val stringsAdapter = StringsAdapter()
    private val hexAdapter = HexAdapter()
    private val disassemblyAdapter = DisassemblyAdapter()

    // Portrait views
    private lateinit var tvFilePath: TextView
    private lateinit var btnPickFile: MaterialButton
    private lateinit var statusBadge: TextView
    private lateinit var infoPanelCard: CardView
    private lateinit var tvElfClass: TextView
    private lateinit var tvElfMachine: TextView
    private lateinit var tvElfEntry: TextView
    private lateinit var tvElfEndian: TextView
    private lateinit var tabLayout: TabLayout
    private lateinit var viewPager: ViewPager2

    // References inside the view pager tabs
    private val tabRecyclerViews = mutableMapOf<Int, RecyclerView>()
    private val tabProgressBars = mutableMapOf<Int, ProgressBar>()
    private val tabEmptyStates = mutableMapOf<Int, View>()

    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ -> }

    private val filePickerLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let { handleSelectedFile(it) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Request POST_NOTIFICATIONS runtime permission on Android 13+ (API 33+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        // Initialize adapters & db
        offsetsDbHelper = OffsetsDatabaseHelper(this)
        functionsAdapter = FunctionsAdapter { selectedFunction ->
            lastSelectedFunction = selectedFunction
            if (resources.configuration.orientation == Configuration.ORIENTATION_LANDSCAPE) {
                loadDisassemblyAndDecompilation(selectedFunction)
            } else {
                viewPager.currentItem = 2
            }
        }

        // Initialize layout based on initial orientation
        initLayout()
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        initLayout()
    }

    private fun initLayout() {
        val isLandscape = resources.configuration.orientation == Configuration.ORIENTATION_LANDSCAPE
        if (isLandscape) {
            setContentView(R.layout.activity_main)

            val etFilter: EditText = findViewById(R.id.et_filter)
            val rvFunctions: RecyclerView = findViewById(R.id.rv_functions)
            val rvHexDisassembly: RecyclerView = findViewById(R.id.rv_hex_disassembly)
            val tvStatusBar: TextView = findViewById(R.id.tv_status_bar)

            rvFunctions.adapter = functionsAdapter
            functionsAdapter.submitList(allFunctionsCached)

            rvHexDisassembly.adapter = disassemblyAdapter

            etFilter.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                    val query = s?.toString() ?: ""
                    filterFunctions(query)
                }
                override fun afterTextChanged(s: android.text.Editable?) {}
            })

            lastSelectedFunction?.let { func ->
                loadDisassemblyAndDecompilation(func)
            } ?: run {
                tvStatusBar.text = if (currentFileName.isNotEmpty()) "$currentFileName | No function selected" else "No file loaded"
                disassemblyAdapter.submitList(listOf("// Select a function from the left panel to begin disassembly & decompilation."))
            }
        } else {
            setContentView(R.layout.activity_main)

            tvFilePath = findViewById(R.id.tv_file_path)
            btnPickFile = findViewById(R.id.btn_pick_file)
            statusBadge = findViewById(R.id.status_badge)
            infoPanelCard = findViewById(R.id.info_panel_card)

            tvElfClass = findViewById(R.id.tv_elf_class)
            tvElfMachine = findViewById(R.id.tv_elf_machine)
            tvElfEntry = findViewById(R.id.tv_elf_entry)
            tvElfEndian = findViewById(R.id.tv_elf_endian)

            tabLayout = findViewById(R.id.tab_layout)
            viewPager = findViewById(R.id.view_pager)

            btnPickFile.setOnClickListener {
                filePickerLauncher.launch("*/*")
            }

            setupViewPager()

            if (currentFileName.isNotEmpty()) {
                tvFilePath.text = currentFileName
                statusBadge.text = "PARSED"
                statusBadge.setTextColor(getColor(R.color.neon_green))

                elfHeaderCached?.let { header ->
                    infoPanelCard.visibility = View.VISIBLE
                    tvElfClass.text = header.classType
                    tvElfMachine.text = header.machine
                    tvElfEntry.text = header.entryPoint
                    tvElfEndian.text = header.endianType
                }

                stringsAdapter.submitList(allStringsCached)
                functionsAdapter.submitList(allFunctionsCached)
                hexAdapter.submitList(allHexCached)

                for (i in 0..2) {
                    tabProgressBars[i]?.visibility = View.GONE
                    tabEmptyStates[i]?.visibility = View.GONE
                    tabRecyclerViews[i]?.visibility = View.VISIBLE
                }
            }
        }
    }

    private fun setupViewPager() {
        val pagerAdapter = TabPagerAdapter(
            stringsAdapter,
            functionsAdapter,
            hexAdapter
        ) { position, recyclerView, progress, emptyState ->
            tabRecyclerViews[position] = recyclerView
            tabProgressBars[position] = progress
            tabEmptyStates[position] = emptyState

            updateTabPlaceholderState(position)
        }

        viewPager.adapter = pagerAdapter
        viewPager.offscreenPageLimit = 3

        TabLayoutMediator(tabLayout, viewPager) { tab, position ->
            tab.text = when (position) {
                0 -> "STRINGS"
                1 -> "FUNCTIONS"
                2 -> "HEX/DISASM"
                else -> "TAB"
            }
        }.attach()
    }

    private fun handleSelectedFile(uri: Uri) {
        statusBadge.text = "LOADING..."
        statusBadge.setTextColor(getColor(R.color.neon_pink))

        val displayName = getUriDisplayName(uri)
        currentFileName = displayName
        tvFilePath.text = displayName

        for (i in 0..2) {
            tabProgressBars[i]?.visibility = View.VISIBLE
            tabEmptyStates[i]?.visibility = View.GONE
        }

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                contentResolver.openFileDescriptor(uri, "r")?.use { pfd ->
                    val fileChannel = java.io.FileInputStream(pfd.fileDescriptor).channel
                    val size = fileChannel.size()
                    val buffer = fileChannel.map(java.nio.channels.FileChannel.MapMode.READ_ONLY, 0, size)
                    binaryBuffer = buffer

                    val parser = ElfParser(buffer)
                    val header = parser.parseHeader()
                    elfHeaderCached = header

                    val strings = parser.extractStrings()
                    val functions = parser.parseSymbols()
                    val hexDump = parser.getHexDump()

                    allFunctionsCached = functions
                    allStringsCached = strings
                    allHexCached = hexDump

                    offsetsDbHelper.insertOffsetsBulk(displayName, functions, header.classType)

                    withContext(Dispatchers.Main) {
                        statusBadge.text = "PARSED"
                        statusBadge.setTextColor(getColor(R.color.neon_green))

                        if (header.isElf) {
                            infoPanelCard.visibility = View.VISIBLE
                            tvElfClass.text = header.classType
                            tvElfMachine.text = header.machine
                            tvElfEntry.text = header.entryPoint
                            tvElfEndian.text = header.endianType
                        } else {
                            infoPanelCard.visibility = View.VISIBLE
                            tvElfClass.text = "RAW DATA (Non-ELF)"
                            tvElfMachine.text = "N/A"
                            tvElfEntry.text = "0x0"
                            tvElfEndian.text = "System Default"
                        }

                        stringsAdapter.submitList(strings)
                        functionsAdapter.submitList(functions)
                        hexAdapter.submitList(hexDump)

                        for (i in 0..2) {
                            tabProgressBars[i]?.visibility = View.GONE
                            tabEmptyStates[i]?.visibility = View.GONE
                            tabRecyclerViews[i]?.visibility = View.VISIBLE
                        }
                    }
                }
            } catch (e: Exception) {
                e.printStackTrace()
                withContext(Dispatchers.Main) {
                    statusBadge.text = "ERR_READ"
                    statusBadge.setTextColor(getColor(R.color.neon_pink))
                    tvFilePath.text = "Error reading binary: ${e.localizedMessage}"

                    for (i in 0..2) {
                        tabProgressBars[i]?.visibility = View.GONE
                        tabEmptyStates[i]?.visibility = View.VISIBLE
                    }
                }
            }
        }
    }

    private fun loadDisassemblyAndDecompilation(func: ElfParser.ElfFunction) {
        val buffer = binaryBuffer ?: return
        val tvStatusBar: TextView? = findViewById(R.id.tv_status_bar)

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val addressHex = func.address.replace("0x", "").replace("0X", "")
                val addressVal = addressHex.toLongOrNull(16) ?: 0L

                val sizeStr = func.size.replace("SIZE:", "").replace("bytes", "").trim()
                val sizeVal = sizeStr.toLongOrNull()?.coerceAtLeast(32L) ?: 128L

                val bytes = ByteArray(sizeVal.toInt())
                val dup = buffer.duplicate()
                if (addressVal >= 0 && addressVal + sizeVal <= dup.capacity()) {
                    dup.position(addressVal.toInt())
                    dup.get(bytes)
                } else {
                    val safeSize = (dup.capacity() - addressVal.toInt()).coerceAtLeast(0).coerceAtMost(sizeVal.toInt())
                    if (safeSize > 0) {
                        val safeBytes = ByteArray(safeSize)
                        dup.position(addressVal.toInt())
                        dup.get(safeBytes)
                        System.arraycopy(safeBytes, 0, bytes, 0, safeSize)
                    }
                }

                val parser = ElfParser(buffer)
                val asmLines = parser.disassembleNative(bytes, addressVal, sizeVal)
                val decompiledCode = parser.decompileNative(bytes, addressVal, sizeVal)

                val decLines = decompiledCode.split("\n")

                val combinedLines = mutableListOf<String>()
                combinedLines.add("// --- DISASSEMBLY (BASE: ${func.address}) ---")
                combinedLines.addAll(asmLines)
                combinedLines.add("")
                combinedLines.add("// --- DECOMPILED PSEUDOCODE ---")
                combinedLines.addAll(decLines)

                withContext(Dispatchers.Main) {
                    disassemblyAdapter.submitList(combinedLines)
                    tvStatusBar?.text = "ELF64 | TARGET: ${func.name} | ADDRESS: ${func.address} | ${func.size}"
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    disassemblyAdapter.submitList(listOf("Error during JNI analysis: ${e.localizedMessage}"))
                }
            }
        }
    }

    private fun filterFunctions(query: String) {
        lifecycleScope.launch(Dispatchers.Default) {
            val filtered = if (query.isBlank()) {
                allFunctionsCached
            } else {
                allFunctionsCached.filter {
                    it.name.contains(query, ignoreCase = true) ||
                    it.address.contains(query, ignoreCase = true)
                }
            }
            withContext(Dispatchers.Main) {
                functionsAdapter.submitList(filtered)
            }
        }
    }

    private fun updateTabPlaceholderState(position: Int) {
        if (binaryBuffer == null) {
            tabEmptyStates[position]?.visibility = View.VISIBLE
            tabProgressBars[position]?.visibility = View.GONE
            tabRecyclerViews[position]?.visibility = View.GONE
        } else {
            tabEmptyStates[position]?.visibility = View.GONE
            tabRecyclerViews[position]?.visibility = View.VISIBLE
        }
    }

    private fun getUriDisplayName(uri: Uri): String {
        var name = uri.path ?: "Unknown_file"
        try {
            contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                val nameIndex = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                if (nameIndex != -1 && cursor.moveToFirst()) {
                    name = cursor.getString(nameIndex)
                }
            }
        } catch (e: Exception) {
            val index = name.lastIndexOf(File.separator)
            if (index != -1) {
                name = name.substring(index + 1)
            }
        }
        return name
    }
}

// --- VIEW PAGER 2 ADAPTER ---

class TabPagerAdapter(
    private val stringsAdapter: StringsAdapter,
    private val functionsAdapter: FunctionsAdapter,
    private val hexAdapter: HexAdapter,
    private val onInitTab: (position: Int, recyclerView: RecyclerView, progress: ProgressBar, emptyState: View) -> Unit
) : RecyclerView.Adapter<TabPagerAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val recyclerView: RecyclerView = view.findViewById(R.id.recycler_view)
        val progress: ProgressBar = view.findViewById(R.id.loading_indicator)
        val emptyState: View = view.findViewById(R.id.empty_state)
    }

    override fun getItemCount(): Int = 3

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.tab_recycler, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        // Optimize RecyclerView performance
        holder.recyclerView.setHasFixedSize(true)
        holder.recyclerView.setItemViewCacheSize(100) // Keep parsed views ready for ultra-smooth scrolling
        holder.recyclerView.isNestedScrollingEnabled = false

        when (position) {
            0 -> holder.recyclerView.adapter = stringsAdapter
            1 -> holder.recyclerView.adapter = functionsAdapter
            2 -> holder.recyclerView.adapter = hexAdapter
        }
        onInitTab(position, holder.recyclerView, holder.progress, holder.emptyState)
    }
}

