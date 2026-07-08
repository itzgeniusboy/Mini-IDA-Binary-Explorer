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
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.platform.ComposeView
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.ui.graphics.Color
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.setViewTreeLifecycleOwner
import androidx.lifecycle.setViewTreeViewModelStoreOwner
import androidx.savedstate.setViewTreeSavedStateRegistryOwner
import androidx.recyclerview.widget.RecyclerView
import androidx.viewpager2.widget.ViewPager2
import com.google.android.material.button.MaterialButton
import com.google.android.material.tabs.TabLayout
import com.google.android.material.tabs.TabLayoutMediator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.yield
import android.app.Dialog
import android.content.Context
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
    private var allDisassemblyCached: List<DisassemblyLine> = emptyList()

    private val minimapVisibleStartAddr = androidx.compose.runtime.mutableStateOf(0L)
    private val minimapVisibleEndAddr = androidx.compose.runtime.mutableStateOf(0L)
    private val minimapFunctions = androidx.compose.runtime.mutableStateOf<List<ElfParser.ElfFunction>>(emptyList())
    private val minimapBookmarks = androidx.compose.runtime.mutableStateOf<List<BookmarkEntry>>(emptyList())

    private val textSectionState = androidx.compose.runtime.mutableStateOf<ElfParser.TextSectionInfo?>(null)
    private var textSectionCached: ElfParser.TextSectionInfo?
        get() = textSectionState.value
        set(value) {
            textSectionState.value = value
        }

    private var isXrefPreScanned: Boolean = true
    private var disassembledOffset: Int = 0
    private val DISASSEMBLY_CHUNK_SIZE = 128 * 1024 // 128KB chunks
    private var loadJob: kotlinx.coroutines.Job? = null

    private var exportFormatSelected: ExportFormat = ExportFormat.JSON
    private var exportSectionsSelected: Set<ExportSection> = emptySet()

    private val createDocumentLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("*/*")
    ) { uri: Uri? ->
        if (uri != null) {
            performExport(uri)
        }
    }

    // Adapters
    private lateinit var functionsAdapter: FunctionsAdapter
    private val stringsAdapter = StringsAdapter()
    private val hexAdapter = HexAdapter()
    private val disassemblyAdapter = DisassemblyAdapter()

    // Global Search UI and State
    private var etGlobalSearch: EditText? = null
    private var pbSearchLoading: ProgressBar? = null
    private var cardSearchResults: CardView? = null
    private var rvSearchResults: RecyclerView? = null
    private var tvCloseSearch: TextView? = null
    private lateinit var searchResultsAdapter: SearchResultsAdapter
    private var searchJob: kotlinx.coroutines.Job? = null

    // Navigation and back/forward buttons
    private var btnDisasmBack: android.widget.Button? = null
    private var btnDisasmForward: android.widget.Button? = null

    private val navigationController = NavigationController { targetAddress ->
        scrollToDisassemblyAddress(targetAddress)
        updateNavigationButtons()
    }

    private val disassemblyTabAdapter = DisassemblyTabAdapter(
        onItemClick = { line ->
            val target = XrefAnalyzer.extractTargetAddress(line.opStr)
            if (target != null) {
                if (allDisassemblyCached.isNotEmpty() && target >= allDisassemblyCached.first().address && target <= allDisassemblyCached.last().address) {
                    navigateToAddress(target)
                }
            }
        },
        onItemLongClick = { view, line ->
            val popup = androidx.appcompat.widget.PopupMenu(this@MainActivity, view)
            popup.menu.add("Add/Edit Comment")
            popup.menu.add("View bytes in Hex")
            popup.setOnMenuItemClickListener { menuItem ->
                when (menuItem.title) {
                    "Add/Edit Comment" -> {
                        showAnnotationDialog(line.address, "0x" + line.address.toString(16).uppercase())
                        true
                    }
                    "View bytes in Hex" -> {
                        navigateToHexAddress(line.address, line.bytesHex.length / 2)
                        true
                    }
                    else -> false
                }
            }
            popup.show()
            true
        }
    )

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
        functionsAdapter = FunctionsAdapter(
            onItemClick = { selectedFunction ->
                lastSelectedFunction = selectedFunction
                val addrHex = selectedFunction.address.removePrefix("0x")
                val addressLong = addrHex.toLongOrNull(16)
                if (addressLong != null) {
                    showXrefDialog(addressLong, selectedFunction.name)
                }
            },
            onItemLongClick = { selectedFunction ->
                val addrHex = selectedFunction.address.removePrefix("0x")
                val addressLong = addrHex.toLongOrNull(16)
                if (addressLong != null) {
                    showAnnotationDialog(addressLong, selectedFunction.name)
                }
                true
            },
            onAcceptSuggestion = { selectedFunction, signatureMatch ->
                val addrHex = selectedFunction.address.removePrefix("0x").removePrefix("0X")
                val addressLong = addrHex.toLongOrNull(16)
                if (addressLong != null) {
                    val fileId = currentFileName ?: ""
                    AnnotationRepository.upsertAnnotation(
                        this@MainActivity,
                        fileId,
                        addressLong,
                        signatureMatch.functionName,
                        "Accepted signature suggestion"
                    )
                    SignatureMatcher.removeSuggestion(addressLong)
                    
                    // Refresh all views and minimap
                    disassemblyTabAdapter.notifyDataSetChanged()
                    functionsAdapter.notifyDataSetChanged()
                    stringsAdapter.notifyDataSetChanged()
                    minimapBookmarks.value = BookmarkRepository.getAllBookmarks()
                    updateMinimapState()
                    
                    android.widget.Toast.makeText(
                        this@MainActivity,
                        "Accepted suggestion: ${signatureMatch.functionName}",
                        android.widget.Toast.LENGTH_SHORT
                    ).show()
                }
            },
            onDismissSuggestion = { selectedFunction ->
                val addrHex = selectedFunction.address.removePrefix("0x").removePrefix("0X")
                val addressLong = addrHex.toLongOrNull(16)
                if (addressLong != null) {
                    SignatureMatcher.removeSuggestion(addressLong)
                    
                    // Refresh views
                    disassemblyTabAdapter.notifyDataSetChanged()
                    functionsAdapter.notifyDataSetChanged()
                    stringsAdapter.notifyDataSetChanged()
                    updateMinimapState()
                    
                    android.widget.Toast.makeText(
                        this@MainActivity,
                        "Dismissed suggestion",
                        android.widget.Toast.LENGTH_SHORT
                    ).show()
                }
            }
        )

        stringsAdapter.getXrefCount = { address ->
            val fileId = currentFileName ?: ""
            if (fileId.isNotEmpty()) {
                offsetsDbHelper.getXrefsTo(fileId, address).size
            } else {
                0
            }
        }
        stringsAdapter.onXrefClick = { str ->
            val addressLong = str.offset.removePrefix("0x").toLongOrNull(16)
            if (addressLong != null) {
                showStringXrefsDialog(addressLong, str.value)
            }
        }

        disassemblyTabAdapter.resolveDataXrefText = { address ->
            val fileId = currentFileName ?: ""
            if (fileId.isNotEmpty()) {
                val xrefs = offsetsDbHelper.getXrefsFrom(fileId, address)
                val dataXref = xrefs.find { it.type == "string_ref" || it.type == "data_ref" }
                if (dataXref != null) {
                    if (dataXref.type == "string_ref") {
                        val strObj = allStringsCached.find {
                            val strAddr = it.offset.removePrefix("0x").toLongOrNull(16) ?: 0L
                            strAddr == dataXref.toAddr
                        }
                        if (strObj != null) {
                            "\"${strObj.value}\""
                        } else {
                            "[string_ref: 0x${dataXref.toAddr.toString(16).uppercase()}]"
                        }
                    } else {
                        "[data_ref: 0x${dataXref.toAddr.toString(16).uppercase()}]"
                    }
                } else {
                    null
                }
            } else {
                null
            }
        }

        hexAdapter.onByteClick = { clickedAddress ->
            val textSec = textSectionCached
            if (textSec != null) {
                val startOffset = textSec.fileOffset
                val endOffset = startOffset + textSec.bytes.size
                if (clickedAddress >= startOffset && clickedAddress < endOffset) {
                    val relativeOffset = clickedAddress - startOffset
                    val virtualAddress = textSec.virtualAddress + relativeOffset
                    
                    val matchedLine = findDisassemblyLineForAddress(virtualAddress)
                    if (matchedLine != null) {
                        navigateToAddress(matchedLine.address)
                    } else {
                        navigateToAddress(virtualAddress)
                    }
                } else {
                    android.widget.Toast.makeText(this@MainActivity, "This address is not in an executable region", android.widget.Toast.LENGTH_SHORT).show()
                }
            } else {
                android.widget.Toast.makeText(this@MainActivity, "This address is not in an executable region", android.widget.Toast.LENGTH_SHORT).show()
            }
        }

        disassemblyTabAdapter.onBookmarkToggle = { line ->
            val defaultLabel = AnnotationRepository.resolveAddressName(line.address)
            toggleBookmarkWithDialog(line.address, defaultLabel)
        }

        functionsAdapter.onBookmarkToggle = { func ->
            val addrHex = func.address.removePrefix("0x")
            val addressLong = addrHex.toLongOrNull(16) ?: 0L
            if (addressLong != 0L) {
                val defaultLabel = AnnotationRepository.resolveAddressName(addressLong)
                toggleBookmarkWithDialog(addressLong, defaultLabel)
            }
        }

        stringsAdapter.onBookmarkToggle = { str ->
            val addressLong = str.offset.removePrefix("0x").toLongOrNull(16) ?: 0L
            if (addressLong != 0L) {
                toggleBookmarkWithDialog(addressLong, str.value)
            }
        }

        // Initialize layout based on initial orientation
        initLayout()

        // Auto-clean extracted libs older than 7 days
        lifecycleScope.launch(Dispatchers.IO) {
            ApkInspector.clearCache(this@MainActivity, maxAgeDays = 7)
        }
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
            setupGlobalSearch()

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
                disassemblyTabAdapter.submitList(allDisassemblyCached)

                for (i in 0..3) {
                    tabProgressBars[i]?.visibility = View.GONE
                    tabEmptyStates[i]?.visibility = View.GONE
                    tabRecyclerViews[i]?.visibility = View.VISIBLE
                }

                tabRecyclerViews[3]?.post {
                    updateMinimapState()
                }
            }
        }

        val btnShowBookmarks: android.widget.ImageButton? = findViewById(R.id.btn_show_bookmarks)
        btnShowBookmarks?.setOnClickListener {
            showBookmarksDialog()
        }
    }

    private fun setupViewPager() {
        val pagerAdapter = TabPagerAdapter(
            stringsAdapter,
            functionsAdapter,
            hexAdapter,
            disassemblyTabAdapter
        ) { position, itemView, recyclerView, progress, emptyState ->
            tabRecyclerViews[position] = recyclerView
            tabProgressBars[position] = progress
            tabEmptyStates[position] = emptyState

            if (position == 3) {
                recyclerView.addOnScrollListener(object : androidx.recyclerview.widget.RecyclerView.OnScrollListener() {
                    override fun onScrolled(rv: androidx.recyclerview.widget.RecyclerView, dx: Int, dy: Int) {
                        val layoutManager = rv.layoutManager as? androidx.recyclerview.widget.LinearLayoutManager
                        if (layoutManager != null) {
                            val totalItemCount = layoutManager.itemCount
                            val lastVisible = layoutManager.findLastVisibleItemPosition()
                            if (lastVisible >= totalItemCount - 50) {
                                loadNextDisassemblyChunk()
                            }
                            updateMinimapScrollPosition()
                        }
                    }
                })

                val minimapComposeView: androidx.compose.ui.platform.ComposeView? = itemView.findViewById(R.id.minimap_compose_view)
                minimapComposeView?.apply {
                    setViewTreeLifecycleOwner(this@MainActivity)
                    setViewTreeViewModelStoreOwner(this@MainActivity)
                    setViewTreeSavedStateRegistryOwner(this@MainActivity)
                    setContent {
                        val textSection = textSectionCached
                        if (textSection != null) {
                            minimapComposeView.visibility = View.VISIBLE
                            NavigationMinimap(
                                textSectionStart = textSection.virtualAddress,
                                textSectionSize = textSection.bytes.size.toLong(),
                                functions = minimapFunctions.value,
                                visibleStartAddr = minimapVisibleStartAddr.value,
                                visibleEndAddr = minimapVisibleEndAddr.value,
                                bookmarks = minimapBookmarks.value,
                                onNavigateToAddress = { targetAddress ->
                                    navigateToAddress(targetAddress)
                                }
                            )
                        } else {
                            minimapComposeView.visibility = View.GONE
                        }
                    }
                }

                val etDisasmFilter: EditText? = itemView.findViewById(R.id.et_disasm_filter)
                etDisasmFilter?.addTextChangedListener(object : android.text.TextWatcher {
                    override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                    override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                        val query = s?.toString() ?: ""
                        filterDisassembly(query)
                    }
                    override fun afterTextChanged(s: android.text.Editable?) {}
                })

                val btnBack: android.widget.Button? = itemView.findViewById(R.id.btn_disasm_back)
                val btnForward: android.widget.Button? = itemView.findViewById(R.id.btn_disasm_forward)

                btnBack?.setOnClickListener {
                    navigationController.goBack()
                }
                btnForward?.setOnClickListener {
                    navigationController.goForward()
                }

                btnDisasmBack = btnBack
                btnDisasmForward = btnForward
                updateNavigationButtons()
            }

            updateTabPlaceholderState(position)
        }

        viewPager.adapter = pagerAdapter
        viewPager.offscreenPageLimit = 4

        TabLayoutMediator(tabLayout, viewPager) { tab, position ->
            when (position) {
                0 -> {
                    tab.text = "STRINGS"
                    tab.icon = getDrawable(android.R.drawable.ic_menu_search)
                }
                1 -> {
                    tab.text = "FUNCTIONS"
                    tab.icon = getDrawable(android.R.drawable.ic_menu_info_details)
                }
                2 -> {
                    tab.text = "HEX"
                    tab.icon = getDrawable(android.R.drawable.ic_menu_view)
                }
                3 -> {
                    tab.text = "DISASM"
                    tab.icon = getDrawable(android.R.drawable.ic_menu_compass)
                }
            }
        }.attach()
    }

    private fun handleSelectedFile(uri: Uri) {
        val displayName = getUriDisplayName(uri)
        val mimeType = contentResolver.getType(uri)
        val isApk = displayName.endsWith(".apk", ignoreCase = true) || 
                    mimeType == "application/vnd.android.package-archive"

        if (isApk) {
            processApkFile(uri, displayName)
        } else {
            loadElfFile(uri, displayName)
        }
    }

    private fun processApkFile(uri: Uri, displayName: String) {
        statusBadge.text = "INSPECTING..."
        statusBadge.setTextColor(getColor(R.color.neon_pink))

        lifecycleScope.launch(Dispatchers.IO) {
            val fileId = ApkInspector.getApkFileId(this@MainActivity, uri)
            val result = ApkInspector.inspectApk(this@MainActivity, uri)

            withContext(Dispatchers.Main) {
                if (!result.isValidApk) {
                    statusBadge.text = "ERR_APK"
                    statusBadge.setTextColor(getColor(R.color.neon_pink))
                    tvFilePath.text = result.errorMessage ?: "Invalid APK file."
                    android.widget.Toast.makeText(
                        this@MainActivity,
                        result.errorMessage ?: "Invalid APK file",
                        android.widget.Toast.LENGTH_LONG
                    ).show()
                    return@withContext
                }

                if (result.nativeLibs.isEmpty()) {
                    statusBadge.text = "NO_LIBS"
                    statusBadge.setTextColor(getColor(R.color.neon_pink))
                    tvFilePath.text = "No native libraries (.so) found in APK"
                    android.widget.Toast.makeText(
                        this@MainActivity,
                        "No native (.so) libraries found in this APK.",
                        android.widget.Toast.LENGTH_LONG
                    ).show()
                    return@withContext
                }

                // Show the Jetpack Compose dialog picker
                ApkLibraryPicker.show(
                    context = this@MainActivity,
                    apkUri = uri,
                    fileId = fileId,
                    nativeLibs = result.nativeLibs,
                    onLibraryExtracted = { extractedFile, customDisplayName ->
                        val fileUri = Uri.fromFile(extractedFile)
                        loadElfFile(
                            fileUri,
                            customDisplayName,
                            fromApkPicker = true,
                            originalApkUri = uri,
                            originalApkDisplayName = displayName
                        )
                    },
                    onDismiss = {
                        if (binaryBuffer == null) {
                            statusBadge.text = "IDLE"
                            statusBadge.setTextColor(getColor(R.color.neon_green))
                            tvFilePath.text = "No file loaded"
                        } else {
                            statusBadge.text = "PARSED"
                            statusBadge.setTextColor(getColor(R.color.neon_green))
                            tvFilePath.text = currentFileName
                        }
                    }
                )
            }
        }
    }

    private var loadingDialog: Dialog? = null
    private val loadingProgressState = mutableStateOf<LoadProgress?>(null)
    private var isUiInitializedEarly = false
    private var isDisassemblingChunk = false

    private fun loadElfFile(
        uri: Uri,
        displayName: String,
        fromApkPicker: Boolean = false,
        originalApkUri: Uri? = null,
        originalApkDisplayName: String? = null
    ) {
        checkMemoryAndWarn(uri, displayName, fromApkPicker, originalApkUri, originalApkDisplayName) {
            startElfProgressiveLoad(uri, displayName)
        }
    }

    private fun checkMemoryAndWarn(
        uri: Uri,
        displayName: String,
        fromApkPicker: Boolean,
        originalApkUri: Uri?,
        originalApkDisplayName: String?,
        onProceed: () -> Unit
    ) {
        val activityManager = getSystemService(Context.ACTIVITY_SERVICE) as android.app.ActivityManager
        val memoryInfo = android.app.ActivityManager.MemoryInfo()
        activityManager.getMemoryInfo(memoryInfo)

        var fileSize = 0L
        try {
            contentResolver.openFileDescriptor(uri, "r")?.use { pfd ->
                fileSize = pfd.statSize
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }

        val availableRam = memoryInfo.availMem
        val totalRam = memoryInfo.totalMem
        val isLowRam = activityManager.isLowRamDevice

        // Heuristic: file size > 40% of available RAM, or low-RAM device with file > 20MB
        val isRisk = (fileSize > 0 && fileSize > (availableRam * 0.40)) || (isLowRam && fileSize > 20 * 1024 * 1024)

        if (isRisk) {
            showLowRamWarningDialog(fileSize, availableRam, totalRam, fromApkPicker, onProceed, {
                statusBadge.text = "IDLE"
                statusBadge.setTextColor(getColor(R.color.neon_green))
                if (binaryBuffer == null) tvFilePath.text = "No file loaded"
            }, {
                if (originalApkUri != null && originalApkDisplayName != null) {
                    processApkFile(originalApkUri, originalApkDisplayName)
                }
            })
        } else {
            onProceed()
        }
    }

    private fun showLowRamWarningDialog(
        fileSize: Long,
        availableRam: Long,
        totalRam: Long,
        fromApkPicker: Boolean,
        onProceed: () -> Unit,
        onCancel: () -> Unit,
        onChooseDifferentAbi: () -> Unit
    ) {
        val dialog = Dialog(this)
        dialog.setCancelable(true)
        dialog.setCanceledOnTouchOutside(false)

        val composeView = ComposeView(this).apply {
            setViewTreeLifecycleOwner(this@MainActivity)
            setViewTreeViewModelStoreOwner(this@MainActivity)
            setViewTreeSavedStateRegistryOwner(this@MainActivity)
            setContent {
                MaterialTheme(
                    colorScheme = darkColorScheme(
                        background = Color(0xFF090A0F),
                        surface = Color(0xFF121420),
                        primary = Color(0xFF00FF66),
                        secondary = Color(0xFF00E5FF),
                        onBackground = Color(0xFFF1F5F9),
                        onSurface = Color(0xFFF1F5F9)
                    )
                ) {
                    LowRamWarningScreen(
                        fileSize = fileSize,
                        availableRam = availableRam,
                        totalRam = totalRam,
                        fromApkPicker = fromApkPicker,
                        onProceed = {
                            dialog.dismiss()
                            onProceed()
                        },
                        onCancel = {
                            dialog.dismiss()
                            onCancel()
                        },
                        onChooseDifferentAbi = {
                            dialog.dismiss()
                            onChooseDifferentAbi()
                        }
                    )
                }
            }
        }

        dialog.setContentView(composeView)
        dialog.show()

        dialog.window?.decorView?.let { decorView ->
            decorView.setViewTreeLifecycleOwner(this@MainActivity)
            decorView.setViewTreeViewModelStoreOwner(this@MainActivity)
            decorView.setViewTreeSavedStateRegistryOwner(this@MainActivity)
        }

        dialog.window?.apply {
            setBackgroundDrawableResource(android.R.color.transparent)
            setLayout(
                android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
    }

    private fun startElfProgressiveLoad(uri: Uri, displayName: String) {
        statusBadge.text = "LOADING..."
        statusBadge.setTextColor(getColor(R.color.neon_pink))
        isUiInitializedEarly = false
        findViewById<androidx.cardview.widget.CardView>(R.id.card_analysis_status)?.visibility = View.GONE

        currentFileName = displayName
        tvFilePath.text = displayName

        for (i in 0..3) {
            tabProgressBars[i]?.visibility = View.VISIBLE
            tabEmptyStates[i]?.visibility = View.GONE
        }

        loadJob?.cancel()
        loadingProgressState.value = null

        showLoadingDialog {
            loadJob?.cancel()
            statusBadge.text = "CANCELLED"
            statusBadge.setTextColor(getColor(R.color.neon_pink))
            tvFilePath.text = "Load cancelled by user"
            for (i in 0..3) {
                tabProgressBars[i]?.visibility = View.GONE
                tabEmptyStates[i]?.visibility = View.VISIBLE
            }
        }

        loadJob = lifecycleScope.launch(Dispatchers.IO) {
            try {
                createLoadFlow(uri, displayName).collect { progress ->
                    withContext(Dispatchers.Main) {
                        loadingProgressState.value = progress
                        updatePersistentStatusCard(progress)
                    }
                }
            } catch (e: CancellationException) {
                withContext(Dispatchers.Main) {
                    loadingDialog?.dismiss()
                    findViewById<androidx.cardview.widget.CardView>(R.id.card_analysis_status)?.visibility = View.GONE
                    statusBadge.text = "CANCELLED"
                    statusBadge.setTextColor(getColor(R.color.neon_pink))
                    tvFilePath.text = "Load cancelled by user"
                }
            } catch (e: Exception) {
                e.printStackTrace()
                withContext(Dispatchers.Main) {
                    loadingDialog?.dismiss()
                    findViewById<androidx.cardview.widget.CardView>(R.id.card_analysis_status)?.visibility = View.GONE
                    statusBadge.text = "ERR_READ"
                    statusBadge.setTextColor(getColor(R.color.neon_pink))
                    tvFilePath.text = "Error reading binary: ${e.localizedMessage}"
                    for (i in 0..3) {
                        tabProgressBars[i]?.visibility = View.GONE
                        tabEmptyStates[i]?.visibility = View.VISIBLE
                    }
                }
            }
        }
    }

    private fun showLoadingDialog(onCancel: () -> Unit) {
        val dialog = Dialog(this)
        dialog.setCancelable(false)
        dialog.setCanceledOnTouchOutside(false)

        val composeView = ComposeView(this).apply {
            setViewTreeLifecycleOwner(this@MainActivity)
            setViewTreeViewModelStoreOwner(this@MainActivity)
            setViewTreeSavedStateRegistryOwner(this@MainActivity)
            setContent {
                MaterialTheme(
                    colorScheme = darkColorScheme(
                        background = Color(0xFF090A0F),
                        surface = Color(0xFF121420),
                        primary = Color(0xFF00FF66),
                        secondary = Color(0xFF00E5FF),
                        onBackground = Color(0xFFF1F5F9),
                        onSurface = Color(0xFFF1F5F9)
                    )
                ) {
                    LoadingProgressScreen(
                        progress = loadingProgressState.value,
                        onCancel = {
                            dialog.dismiss()
                            onCancel()
                        }
                    )
                }
            }
        }

        dialog.setContentView(composeView)
        dialog.show()

        dialog.window?.decorView?.let { decorView ->
            decorView.setViewTreeLifecycleOwner(this@MainActivity)
            decorView.setViewTreeViewModelStoreOwner(this@MainActivity)
            decorView.setViewTreeSavedStateRegistryOwner(this@MainActivity)
        }

        dialog.window?.apply {
            setBackgroundDrawableResource(android.R.color.transparent)
            setLayout(
                android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
        loadingDialog = dialog
    }

    private fun checkAndInitializeUiEarly(header: ElfParser.ElfHeader) {
        if (isUiInitializedEarly) return
        isUiInitializedEarly = true

        loadingDialog?.dismiss()
        statusBadge.text = "ANALYZING"
        statusBadge.setTextColor(getColor(R.color.neon_cyan))

        navigationController.clear()
        disassemblyTabAdapter.setHighlightAddress(null)
        updateNavigationButtons()

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

        stringsAdapter.submitList(allStringsCached)
        functionsAdapter.submitList(allFunctionsCached)
        hexAdapter.submitList(allHexCached)
        
        if (allDisassemblyCached.isEmpty() && loadingProgressState.value?.stage != LoadStage.DONE) {
            disassemblyTabAdapter.submitList(listOf(
                DisassemblyLine(
                    address = -1L,
                    bytesHex = "",
                    mnemonic = "// [STILL ANALYZING THIS SECTION...]",
                    opStr = "The main .text segment is being extracted and disassembled incrementally..."
                )
            ))
        } else {
            disassemblyTabAdapter.submitList(allDisassemblyCached)
        }

        for (i in 0..3) {
            tabProgressBars[i]?.visibility = View.GONE
            tabEmptyStates[i]?.visibility = View.GONE
            tabRecyclerViews[i]?.visibility = View.VISIBLE
        }

        tabRecyclerViews[3]?.post {
            updateMinimapState()
        }
    }

    private fun updatePersistentStatusCard(progress: LoadProgress?) {
        val cardAnalysisStatus: androidx.cardview.widget.CardView? = findViewById(R.id.card_analysis_status)
        if (cardAnalysisStatus == null) return

        if (progress == null || progress.stage == LoadStage.DONE || progress.stage == LoadStage.ERROR) {
            cardAnalysisStatus.visibility = View.GONE
            if (progress?.stage == LoadStage.DONE) {
                statusBadge.text = "PARSED"
                statusBadge.setTextColor(getColor(R.color.neon_green))
            }
            return
        }

        cardAnalysisStatus.visibility = View.VISIBLE

        val tvLabel: TextView? = findViewById(R.id.tv_analysis_status_label)
        val tvProgress: TextView? = findViewById(R.id.tv_analysis_status_progress)
        val tvDetails: TextView? = findViewById(R.id.tv_analysis_status_details)
        val pbStatus: ProgressBar? = findViewById(R.id.pb_analysis_status)
        val btnCancelAnalysis: TextView? = findViewById(R.id.btn_cancel_analysis)

        val progressFraction = when (progress.stage) {
            LoadStage.READING_HEADER -> 0.15f
            LoadStage.PARSING_SECTIONS -> 0.35f
            LoadStage.EXTRACTING_SYMBOLS -> 0.50f
            LoadStage.EXTRACTING_STRINGS -> 0.65f
            LoadStage.INDEXING_DB -> 0.80f
            LoadStage.MATCHING_SIGNATURES -> 0.90f
            LoadStage.RESOLVING_DATA_XREFS -> 0.95f
            LoadStage.DONE -> 1.0f
            LoadStage.ERROR -> 1.0f
        }

        val percentage = (progressFraction * 100).toInt()
        tvLabel?.text = "ANALYZING BINARY (${progress.stage.name})..."
        tvProgress?.text = "$percentage%"
        tvDetails?.text = "${progress.detail} (Found ${allFunctionsCached.size} symbols, ${allStringsCached.size} strings)"
        pbStatus?.progress = percentage

        btnCancelAnalysis?.setOnClickListener {
            loadJob?.cancel()
            cardAnalysisStatus.visibility = View.GONE
            statusBadge.text = "CANCELLED"
            statusBadge.setTextColor(getColor(R.color.neon_pink))
            tvFilePath.text = "Load cancelled by user"
            for (i in 0..3) {
                tabProgressBars[i]?.visibility = View.GONE
                tabEmptyStates[i]?.visibility = View.VISIBLE
            }
        }
    }

    private fun createLoadFlow(uri: Uri, displayName: String): Flow<LoadProgress> = flow {
        emit(LoadProgress(LoadStage.READING_HEADER, 0, "Opening binary file and mapping file channel..."))

        val pfd = contentResolver.openFileDescriptor(uri, "r") ?: throw Exception("Failed to open file descriptor")
        pfd.use { fd ->
            val fileChannel = java.io.FileInputStream(fd.fileDescriptor).channel
            val size = fileChannel.size()
            val buffer = fileChannel.map(java.nio.channels.FileChannel.MapMode.READ_ONLY, 0, size)
            binaryBuffer = buffer

            val parser = ElfParser(buffer)
            val header = parser.parseHeader()
            elfHeaderCached = header
            yield()

            emit(LoadProgress(LoadStage.PARSING_SECTIONS, 0, "Analyzing sections and locating program segments..."))
            val textSection = parser.findTextSection()
            textSectionCached = textSection
            yield()

            emit(LoadProgress(LoadStage.EXTRACTING_STRINGS, 0, "Scanning binary for readable ASCII strings..."))
            var lastUpdateMillis = System.currentTimeMillis()
            val stringsBufferList = mutableListOf<ElfParser.ElfString>()
            
            withContext(Dispatchers.Main) {
                allStringsCached = emptyList()
                stringsAdapter.submitList(emptyList())
            }

            val strings = parser.extractStrings(
                maxLimit = 50000,
                onStringFound = { elfString ->
                    stringsBufferList.add(elfString)
                    val now = System.currentTimeMillis()
                    if (stringsBufferList.size >= 500 || now - lastUpdateMillis >= 500) {
                        val batchToEmit = stringsBufferList.toList()
                        stringsBufferList.clear()
                        lastUpdateMillis = now
                        runOnUiThread {
                            allStringsCached = allStringsCached + batchToEmit
                            stringsAdapter.submitList(allStringsCached)
                            checkAndInitializeUiEarly(header)
                        }
                    }
                }
            )

            if (stringsBufferList.isNotEmpty()) {
                val batchToEmit = stringsBufferList.toList()
                stringsBufferList.clear()
                withContext(Dispatchers.Main) {
                    allStringsCached = allStringsCached + batchToEmit
                    stringsAdapter.submitList(allStringsCached)
                    checkAndInitializeUiEarly(header)
                }
            }
            allStringsCached = strings
            withContext(Dispatchers.Main) {
                stringsAdapter.submitList(allStringsCached)
                checkAndInitializeUiEarly(header)
            }
            yield()

            emit(LoadProgress(LoadStage.EXTRACTING_SYMBOLS, 0, "Parsing symbol tables and demangling functions..."))
            var lastFuncUpdateMillis = System.currentTimeMillis()
            val funcsBufferList = mutableListOf<ElfParser.ElfFunction>()

            offsetsDbHelper.clearOffsets(displayName)

            withContext(Dispatchers.Main) {
                allFunctionsCached = emptyList()
                functionsAdapter.submitList(emptyList())
            }

            val rawSymbols = parser.parseSymbols(
                onFunctionFound = { elfFunction ->
                    funcsBufferList.add(elfFunction)
                    val now = System.currentTimeMillis()
                    if (funcsBufferList.size >= 500 || now - lastFuncUpdateMillis >= 500) {
                        val batchToInsert = funcsBufferList.toList()
                        funcsBufferList.clear()
                        lastFuncUpdateMillis = now
                        
                        offsetsDbHelper.insertOffsetsBatch(displayName, batchToInsert, header.classType)
                        
                        runOnUiThread {
                            allFunctionsCached = allFunctionsCached + batchToInsert
                            functionsAdapter.submitList(allFunctionsCached)
                            checkAndInitializeUiEarly(header)
                        }
                    }
                }
            )

            if (funcsBufferList.isNotEmpty()) {
                val batchToInsert = funcsBufferList.toList()
                funcsBufferList.clear()
                offsetsDbHelper.insertOffsetsBatch(displayName, batchToInsert, header.classType)
                withContext(Dispatchers.Main) {
                    allFunctionsCached = allFunctionsCached + batchToInsert
                    functionsAdapter.submitList(allFunctionsCached)
                    checkAndInitializeUiEarly(header)
                }
            }

            val totalSymbolsCount = rawSymbols.size
            val cappedSymbols = if (totalSymbolsCount > 200000) {
                rawSymbols.take(200000) + ElfParser.ElfFunction(
                    address = "NOTICE",
                    name = "Showing first 200,000 of $totalSymbolsCount symbols — use search to find others",
                    size = "",
                    bind = "",
                    type = "",
                    index = -1
                )
            } else {
                rawSymbols
            }
            allFunctionsCached = cappedSymbols
            withContext(Dispatchers.Main) {
                functionsAdapter.submitList(allFunctionsCached)
                checkAndInitializeUiEarly(header)
            }
            yield()

            emit(LoadProgress(LoadStage.INDEXING_DB, allFunctionsCached.size, "Finalizing SQLite offset index..."))
            yield()

            emit(LoadProgress(LoadStage.MATCHING_SIGNATURES, 0, "Auto-identifying common library functions using signatures..."))
            SignatureMatcher.loadSignatures(this@MainActivity)
            SignatureMatcher.clear()

            if (textSection != null && totalSymbolsCount <= 50000) {
                val arch = ElfArch.fromMachineVal(header.machineVal)
                var matchedCount = 0
                rawSymbols.forEachIndexed { idx, f ->
                    if (idx % 1000 == 0) {
                        yield()
                        emit(LoadProgress(LoadStage.MATCHING_SIGNATURES, idx, "Matched $matchedCount function signatures..."))
                    }
                    val name = f.name
                    val isGeneric = name.startsWith("sub_") || name.isBlank() || name == "sub"
                    if (isGeneric) {
                        val addressLong = f.address.removePrefix("0x").removePrefix("0X").toLongOrNull(16)
                        if (addressLong != null) {
                            val textOffset = (addressLong - textSection.virtualAddress).toInt()
                            if (textOffset >= 0 && textOffset < textSection.bytes.size) {
                                val maxLen = minOf(32, textSection.bytes.size - textOffset)
                                if (maxLen > 0) {
                                    val functionBytes = textSection.bytes.copyOfRange(textOffset, textOffset + maxLen)
                                    val match = SignatureMatcher.matchFunction(functionBytes, arch)
                                    if (match != null) {
                                        SignatureMatcher.addSuggestion(addressLong, match)
                                        matchedCount++
                                    }
                                }
                            }
                        }
                    }
                }
                emit(LoadProgress(LoadStage.MATCHING_SIGNATURES, rawSymbols.size, "Auto-identified $matchedCount functions successfully."))
            } else if (textSection != null) {
                emit(LoadProgress(LoadStage.MATCHING_SIGNATURES, 0, "Skipping auto-signature matching (>50k symbols to keep UI responsive)."))
            }
            yield()

            emit(LoadProgress(LoadStage.PARSING_SECTIONS, 0, "Preparing initial disassembly view..."))

            val disassemblyList = if (textSection != null) {
                disassembledOffset = minOf(textSection.bytes.size, DISASSEMBLY_CHUNK_SIZE)
                val initialBytes = textSection.bytes.copyOfRange(0, disassembledOffset)
                val disasmLines = parser.disassembleSection(
                    initialBytes,
                    textSection.virtualAddress,
                    header.machineVal,
                    header.is64Bit
                ) ?: emptyArray()
                disasmLines.toList()
            } else {
                disassembledOffset = 0
                emptyList()
            }
            allDisassemblyCached = disassemblyList
            yield()

            val hexDump = parser.getHexDump()
            allHexCached = hexDump
            yield()

            AnnotationRepository.loadAnnotations(this@MainActivity, displayName)
            AnnotationRepository.setFunctions(cappedSymbols)
            BookmarkRepository.loadBookmarks(this@MainActivity, displayName)

            val estimatedInstructions = if (textSection != null) textSection.bytes.size / 4 else 0
            if (estimatedInstructions > 2000000) {
                isXrefPreScanned = false
                emit(LoadProgress(LoadStage.DONE, 0, "Skipping full XREF scan (>2M instructions). On-demand lookup enabled."))
            } else {
                isXrefPreScanned = true
                emit(LoadProgress(LoadStage.RESOLVING_DATA_XREFS, 0, "Scanning instruction flow for code and data XREFs..."))

                val sections = parser.getSections()
                val fullDisassemblyForXrefs = if (textSection != null) {
                    parser.disassembleSection(
                        textSection.bytes,
                        textSection.virtualAddress,
                        header.machineVal,
                        header.is64Bit
                    ) ?: emptyArray()
                } else {
                    emptyArray()
                }

                val xrefs = withContext(Dispatchers.Default) {
                    XrefAnalyzer.analyze(
                        disassembly = fullDisassemblyForXrefs.toList(),
                        knownStrings = allStringsCached,
                        sections = sections,
                        buffer = binaryBuffer,
                        isLittleEndian = header.isLittleEndian
                    )
                }
                offsetsDbHelper.insertXrefs(displayName, xrefs)
            }
            yield()

            emit(LoadProgress(LoadStage.DONE, 100, "Successfully analyzed binary!"))

            withContext(Dispatchers.Main) {
                checkAndInitializeUiEarly(header)

                loadingDialog?.dismiss()
                statusBadge.text = "PARSED"
                statusBadge.setTextColor(getColor(R.color.neon_green))

                stringsAdapter.submitList(allStringsCached)
                functionsAdapter.submitList(allFunctionsCached)
                hexAdapter.submitList(allHexCached)
                disassemblyTabAdapter.submitList(allDisassemblyCached)

                for (i in 0..3) {
                    tabProgressBars[i]?.visibility = View.GONE
                    tabEmptyStates[i]?.visibility = View.GONE
                    tabRecyclerViews[i]?.visibility = View.VISIBLE
                }

                tabRecyclerViews[3]?.post {
                    updateMinimapState()
                }

                if (!isXrefPreScanned) {
                    android.widget.Toast.makeText(
                        this@MainActivity,
                        "Notice: Full-binary XREF scan skipped due to large size.",
                        android.widget.Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }

    private fun scanXrefsForFunctionOnDemand(func: ElfParser.ElfFunction): List<XrefEntry> {
        val buffer = binaryBuffer ?: return emptyList()
        val addrHex = func.address.replace("0x", "").replace("0X", "")
        val addressVal = addrHex.toLongOrNull(16) ?: return emptyList()

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

        val header = elfHeaderCached ?: return emptyList()
        val parser = ElfParser(buffer)
        val disassembly = parser.disassembleSection(
            bytes,
            addressVal,
            header.machineVal,
            header.is64Bit
        ) ?: return emptyList()
        return XrefAnalyzer.analyze(disassembly.toList())
    }

    private fun loadNextDisassemblyChunk() {
        val textSection = textSectionCached ?: return
        if (disassembledOffset >= textSection.bytes.size) return
        if (isDisassemblingChunk) return

        isDisassemblingChunk = true
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val header = elfHeaderCached ?: return@launch
                val buffer = binaryBuffer ?: return@launch
                val parser = ElfParser(buffer)

                val nextSize = minOf(textSection.bytes.size - disassembledOffset, DISASSEMBLY_CHUNK_SIZE)
                if (nextSize <= 0) return@launch

                val chunkBytes = textSection.bytes.copyOfRange(disassembledOffset, disassembledOffset + nextSize)
                val chunkAddr = textSection.virtualAddress + disassembledOffset

                val chunkLines = parser.disassembleSection(
                    chunkBytes,
                    chunkAddr,
                    header.machineVal,
                    header.is64Bit
                ) ?: emptyArray()

                disassembledOffset += nextSize

                withContext(Dispatchers.Main) {
                    allDisassemblyCached = allDisassemblyCached + chunkLines.toList()
                    disassemblyTabAdapter.submitList(allDisassemblyCached)
                }
            } catch (e: Exception) {
                e.printStackTrace()
            } finally {
                isDisassemblingChunk = false
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

    private fun filterDisassembly(query: String) {
        lifecycleScope.launch(Dispatchers.Default) {
            val filtered = if (query.isBlank()) {
                allDisassemblyCached
            } else {
                allDisassemblyCached.filter {
                    val addrStr = "0x" + it.address.toString(16).uppercase()
                    addrStr.contains(query, ignoreCase = true) ||
                    it.bytesHex.contains(query, ignoreCase = true) ||
                    it.mnemonic.contains(query, ignoreCase = true) ||
                    it.opStr.contains(query, ignoreCase = true)
                }
            }
            withContext(Dispatchers.Main) {
                disassemblyTabAdapter.submitList(filtered)
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

    private fun showXrefDialog(address: Long, title: String) {
        val context = this
        val fileId = currentFileName
        if (fileId.isEmpty()) return

        lifecycleScope.launch(Dispatchers.Default) {
            val calledBy = offsetsDbHelper.getXrefsTo(fileId, address)
            var calls = offsetsDbHelper.getXrefsFrom(fileId, address)

            // Dynamic on-demand analysis if full-scan was skipped
            if (!isXrefPreScanned && calls.isEmpty()) {
                val matchedFunc = allFunctionsCached.find {
                    val funcAddr = it.address.removePrefix("0x").toLongOrNull(16) ?: 0L
                    funcAddr == address
                }
                if (matchedFunc != null) {
                    val onDemandXrefs = scanXrefsForFunctionOnDemand(matchedFunc)
                    if (onDemandXrefs.isNotEmpty()) {
                        offsetsDbHelper.insertXrefs(fileId, onDemandXrefs)
                        calls = onDemandXrefs
                    }
                }
            }

            withContext(Dispatchers.Main) {
                val dialogView = LayoutInflater.from(context).inflate(R.layout.dialog_xref_details, null)
                val tvDialogTitle: TextView = dialogView.findViewById(R.id.tv_dialog_title)
                val containerCalledBy: android.widget.LinearLayout = dialogView.findViewById(R.id.container_called_by)
                val containerCalls: android.widget.LinearLayout = dialogView.findViewById(R.id.container_calls)
                val tvCalledByHeader: TextView = dialogView.findViewById(R.id.tv_called_by_header)
                val tvCallsHeader: TextView = dialogView.findViewById(R.id.tv_calls_header)

                tvDialogTitle.text = "XREFS FOR $title"
                
                if (!isXrefPreScanned) {
                    tvCalledByHeader.text = "CALLED BY (N/A - PRE-SCAN SKIPPED)"
                } else {
                    tvCalledByHeader.text = "CALLED BY (${calledBy.size})"
                }
                tvCallsHeader.text = "CALLS (${calls.size})"

                val dialog = androidx.appcompat.app.AlertDialog.Builder(context)
                    .setView(dialogView)
                    .create()

                // Populate CALLED BY
                if (!isXrefPreScanned) {
                    val infoTv = TextView(context).apply {
                        text = " Incoming references are unavailable because the full-binary pre-scan was skipped for performance."
                        setTextColor(android.graphics.Color.parseColor("#FF007F"))
                        textSize = 12f
                        setPadding(16, 8, 16, 8)
                    }
                    containerCalledBy.addView(infoTv)
                } else if (calledBy.isEmpty()) {
                    val emptyTv = TextView(context).apply {
                        text = " No incoming references found."
                        setTextColor(android.graphics.Color.parseColor("#5A6075"))
                        textSize = 12f
                        setPadding(16, 8, 16, 8)
                    }
                    containerCalledBy.addView(emptyTv)
                } else {
                    for (ref in calledBy) {
                        val itemView = LayoutInflater.from(context).inflate(R.layout.item_xref_list, containerCalledBy, false)
                        val tvRefText: TextView = itemView.findViewById(R.id.tv_xref_text)
                        val fromHex = "0x" + ref.fromAddr.toString(16).uppercase()
                        
                        val resolvedName = AnnotationRepository.resolveAddressName(ref.fromAddr)
                        val label = "$fromHex ($resolvedName)"
                        tvRefText.text = "← $label"
                        
                        itemView.setOnClickListener {
                            dialog.dismiss()
                            navigateToAddress(ref.fromAddr)
                        }
                        containerCalledBy.addView(itemView)
                    }
                }

                // Populate CALLS
                if (calls.isEmpty()) {
                    val emptyTv = TextView(context).apply {
                        text = " No outgoing references found."
                        setTextColor(android.graphics.Color.parseColor("#5A6075"))
                        textSize = 12f
                        setPadding(16, 8, 16, 8)
                    }
                    containerCalls.addView(emptyTv)
                } else {
                    for (ref in calls) {
                        val itemView = LayoutInflater.from(context).inflate(R.layout.item_xref_list, containerCalls, false)
                        val tvRefText: TextView = itemView.findViewById(R.id.tv_xref_text)
                        val toHex = "0x" + ref.toAddr.toString(16).uppercase()

                        val resolvedName = AnnotationRepository.resolveAddressName(ref.toAddr)
                        val label = "$toHex ($resolvedName)"
                        tvRefText.text = "→ $label"

                        itemView.setOnClickListener {
                            dialog.dismiss()
                            navigateToAddress(ref.toAddr)
                        }
                        containerCalls.addView(itemView)
                    }
                }

                dialog.show()
                dialog.window?.setBackgroundDrawableResource(android.R.color.transparent)
            }
        }
    }

    private fun showStringXrefsDialog(address: Long, stringValue: String) {
        val fileId = currentFileName ?: ""
        if (fileId.isEmpty()) return

        lifecycleScope.launch(Dispatchers.Default) {
            val referencingXrefs = offsetsDbHelper.getXrefsTo(fileId, address)

            withContext(Dispatchers.Main) {
                val dialogView = LayoutInflater.from(this@MainActivity).inflate(R.layout.dialog_xref_details, null)
                val tvDialogTitle: TextView = dialogView.findViewById(R.id.tv_dialog_title)
                val containerCalledBy: android.widget.LinearLayout = dialogView.findViewById(R.id.container_called_by)
                val containerCalls: android.widget.LinearLayout = dialogView.findViewById(R.id.container_calls)
                val tvCalledByHeader: TextView = dialogView.findViewById(R.id.tv_called_by_header)
                val tvCallsHeader: TextView = dialogView.findViewById(R.id.tv_calls_header)

                // Hide Calls section
                tvCallsHeader.visibility = View.GONE
                containerCalls.visibility = View.GONE

                val displayTitle = if (stringValue.length > 25) stringValue.substring(0, 22) + "..." else stringValue
                tvDialogTitle.text = "XREFS FOR \"$displayTitle\""
                tvCalledByHeader.text = "REFERENCED BY (${referencingXrefs.size})"

                val dialog = androidx.appcompat.app.AlertDialog.Builder(this@MainActivity)
                    .setView(dialogView)
                    .create()

                if (referencingXrefs.isEmpty()) {
                    val emptyTv = TextView(this@MainActivity).apply {
                        text = " No references found."
                        setTextColor(android.graphics.Color.parseColor("#5A6075"))
                        textSize = 12f
                        setPadding(16, 8, 16, 8)
                    }
                    containerCalledBy.addView(emptyTv)
                } else {
                    for (ref in referencingXrefs) {
                        val itemView = LayoutInflater.from(this@MainActivity).inflate(R.layout.item_xref_list, containerCalledBy, false)
                        val tvRefText: TextView = itemView.findViewById(R.id.tv_xref_text)
                        val fromHex = "0x" + ref.fromAddr.toString(16).uppercase()

                        val resolvedName = AnnotationRepository.resolveAddressName(ref.fromAddr)
                        val label = "$fromHex ($resolvedName)"
                        tvRefText.text = "← $label"

                        itemView.setOnClickListener {
                            dialog.dismiss()
                            navigateToAddress(ref.fromAddr)
                        }
                        containerCalledBy.addView(itemView)
                    }
                }

                dialog.show()
                dialog.window?.setBackgroundDrawableResource(android.R.color.transparent)
            }
        }
    }

    private fun navigateToAddress(address: Long) {
        if (resources.configuration.orientation != Configuration.ORIENTATION_LANDSCAPE) {
            viewPager.currentItem = 3
        }
        navigationController.navigateTo(address)
    }

    private fun toggleBookmarkWithDialog(address: Long, defaultLabel: String) {
        val fileId = currentFileName
        if (fileId.isEmpty()) return

        if (BookmarkRepository.isBookmarked(address)) {
            BookmarkRepository.removeBookmark(this, fileId, address)
            android.widget.Toast.makeText(this, "Bookmark removed", android.widget.Toast.LENGTH_SHORT).show()
            disassemblyTabAdapter.notifyDataSetChanged()
            functionsAdapter.notifyDataSetChanged()
            stringsAdapter.notifyDataSetChanged()
            minimapBookmarks.value = BookmarkRepository.getAllBookmarks()
        } else {
            val input = android.widget.EditText(this).apply {
                setText(defaultLabel)
                setSelection(defaultLabel.length)
            }
            androidx.appcompat.app.AlertDialog.Builder(this)
                .setTitle("Add Bookmark")
                .setMessage("Set a label for address 0x${address.toString(16).uppercase()}:")
                .setView(input)
                .setPositiveButton("Bookmark") { _, _ ->
                    val label = input.text.toString().trim()
                    val finalLabel = if (label.isEmpty()) defaultLabel else label
                    BookmarkRepository.addBookmark(this, fileId, address, finalLabel)
                    android.widget.Toast.makeText(this, "Bookmarked: $finalLabel", android.widget.Toast.LENGTH_SHORT).show()
                    disassemblyTabAdapter.notifyDataSetChanged()
                    functionsAdapter.notifyDataSetChanged()
                    stringsAdapter.notifyDataSetChanged()
                    minimapBookmarks.value = BookmarkRepository.getAllBookmarks()
                }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }

    private fun showBookmarksDialog() {
        val fileId = currentFileName
        if (fileId.isEmpty()) {
            android.widget.Toast.makeText(this, "Please open a file first", android.widget.Toast.LENGTH_SHORT).show()
            return
        }

        val dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_bookmarks, null)
        val containerBookmarks: android.widget.LinearLayout = dialogView.findViewById(R.id.container_bookmarks)
        val btnClose: android.widget.Button = dialogView.findViewById(R.id.btn_close_bookmarks)

        val dialog = androidx.appcompat.app.AlertDialog.Builder(this)
            .setView(dialogView)
            .create()

        btnClose.setOnClickListener {
            dialog.dismiss()
        }

        fun populateBookmarks() {
            containerBookmarks.removeAllViews()
            val bookmarksList = BookmarkRepository.getAllBookmarks().sortedBy { it.address }
            if (bookmarksList.isEmpty()) {
                val emptyTv = TextView(this).apply {
                    text = "No bookmarks set for this file.\nStar addresses in Functions, Disassembly, or Strings tabs to save them."
                    setTextColor(android.graphics.Color.parseColor("#5A6075"))
                    textSize = 12f
                    gravity = android.view.Gravity.CENTER
                    setPadding(16, 48, 16, 48)
                }
                containerBookmarks.addView(emptyTv)
            } else {
                for (b in bookmarksList) {
                    val rowView = LayoutInflater.from(this).inflate(R.layout.item_bookmark_row, containerBookmarks, false)
                    val tvLabel: TextView = rowView.findViewById(R.id.tv_bookmark_label)
                    val tvAddress: TextView = rowView.findViewById(R.id.tv_bookmark_address)
                    val ivRemove: ImageView = rowView.findViewById(R.id.iv_bookmark_remove)

                    tvLabel.text = b.label ?: "0x${b.address.toString(16).uppercase()}"
                    tvAddress.text = "0x" + b.address.toString(16).uppercase().padStart(8, '0')

                    rowView.setOnClickListener {
                        dialog.dismiss()
                        navigateToAddress(b.address)
                    }

                    ivRemove.setOnClickListener {
                        BookmarkRepository.removeBookmark(this, fileId, b.address)
                        android.widget.Toast.makeText(this, "Bookmark removed", android.widget.Toast.LENGTH_SHORT).show()
                        populateBookmarks()
                        
                        // Notify all tabs to update their star states
                        disassemblyTabAdapter.notifyDataSetChanged()
                        functionsAdapter.notifyDataSetChanged()
                        stringsAdapter.notifyDataSetChanged()
                        minimapBookmarks.value = BookmarkRepository.getAllBookmarks()
                    }

                    containerBookmarks.addView(rowView)
                }
            }
        }

        populateBookmarks()
        dialog.show()
        dialog.window?.setBackgroundDrawableResource(android.R.color.transparent)
    }

    private fun updateNavigationButtons() {
        btnDisasmBack?.isEnabled = navigationController.canGoBack()
        btnDisasmForward?.isEnabled = navigationController.canGoForward()
    }

    private fun updateMinimapState() {
        val textSection = textSectionCached
        if (textSection != null) {
            minimapFunctions.value = allFunctionsCached
            minimapBookmarks.value = BookmarkRepository.getAllBookmarks()
            
            // Calculate current visible address range
            val rv = tabRecyclerViews[3]
            val layoutManager = rv?.layoutManager as? androidx.recyclerview.widget.LinearLayoutManager
            if (layoutManager != null) {
                val firstVisible = layoutManager.findFirstVisibleItemPosition()
                val lastVisible = layoutManager.findLastVisibleItemPosition()
                
                val firstLine = allDisassemblyCached.getOrNull(firstVisible)
                val lastLine = allDisassemblyCached.getOrNull(lastVisible)
                
                minimapVisibleStartAddr.value = firstLine?.address ?: textSection.virtualAddress
                minimapVisibleEndAddr.value = lastLine?.address ?: (textSection.virtualAddress + textSection.bytes.size)
            } else {
                minimapVisibleStartAddr.value = textSection.virtualAddress
                minimapVisibleEndAddr.value = textSection.virtualAddress + minOf(textSection.bytes.size.toLong(), DISASSEMBLY_CHUNK_SIZE.toLong())
            }
        } else {
            minimapFunctions.value = emptyList()
            minimapBookmarks.value = emptyList()
            minimapVisibleStartAddr.value = 0L
            minimapVisibleEndAddr.value = 0L
        }
    }

    private fun updateMinimapScrollPosition() {
        val textSection = textSectionCached ?: return
        val rv = tabRecyclerViews[3]
        val layoutManager = rv?.layoutManager as? androidx.recyclerview.widget.LinearLayoutManager
        if (layoutManager != null) {
            val firstVisible = layoutManager.findFirstVisibleItemPosition()
            val lastVisible = layoutManager.findLastVisibleItemPosition()
            
            val firstLine = allDisassemblyCached.getOrNull(firstVisible)
            val lastLine = allDisassemblyCached.getOrNull(lastVisible)
            
            if (firstLine != null) {
                minimapVisibleStartAddr.value = firstLine.address
            }
            if (lastLine != null) {
                minimapVisibleEndAddr.value = lastLine.address
            }
        }
    }

    private fun scrollToDisassemblyAddress(address: Long) {
        val recyclerView = tabRecyclerViews[3]
        if (recyclerView != null) {
            recyclerView.scrollToAddress(
                matcher = { index ->
                    val line = allDisassemblyCached.getOrNull(index)
                    line != null && line.address == address
                },
                onFound = { index ->
                    disassemblyTabAdapter.setHighlightAddress(address)
                }
            )
        }
    }

    private fun navigateToHexAddress(address: Long, length: Int) {
        val textSec = textSectionCached
        if (textSec != null) {
            if (address >= textSec.virtualAddress && address < textSec.virtualAddress + textSec.bytes.size) {
                val relativeOffset = address - textSec.virtualAddress
                val fileOffset = textSec.fileOffset + relativeOffset
                
                if (resources.configuration.orientation != Configuration.ORIENTATION_LANDSCAPE) {
                    viewPager.currentItem = 2 // HEX Tab
                }
                
                scrollToHexOffset(fileOffset, length)
            } else {
                android.widget.Toast.makeText(this, "Address not in text section range.", android.widget.Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun scrollToHexOffset(offset: Long, length: Int) {
        val recyclerView = tabRecyclerViews[2]
        if (recyclerView != null) {
            recyclerView.scrollToAddress(
                matcher = { index ->
                    val row = allHexCached.getOrNull(index)
                    if (row != null) {
                        val baseAddr = row.address.removePrefix("0x").toLongOrNull(16) ?: 0L
                        offset >= baseAddr && offset < baseAddr + 16
                    } else {
                        false
                    }
                },
                onFound = { index ->
                    hexAdapter.setHighlightRange(offset, length)
                }
            )
        }
    }

    private fun findDisassemblyLineForAddress(virtualAddress: Long): DisassemblyLine? {
        return allDisassemblyCached.find { line ->
            val len = line.bytesHex.length / 2
            virtualAddress >= line.address && virtualAddress < line.address + len
        }
    }

    private fun setupGlobalSearch() {
        etGlobalSearch = findViewById(R.id.et_global_search)
        pbSearchLoading = findViewById(R.id.pb_search_loading)
        cardSearchResults = findViewById(R.id.card_search_results)
        rvSearchResults = findViewById(R.id.rv_search_results)
        tvCloseSearch = findViewById(R.id.tv_close_search)

        if (etGlobalSearch == null) return

        searchResultsAdapter = SearchResultsAdapter(
            onSymbolClick = { sym ->
                navigateToAddress(sym.address)
                hideSearchResults()
            },
            onStringClick = { str ->
                navigateToStringAddress(str.address)
                hideSearchResults()
            },
            onAddressClick = { addr ->
                navigateToAddress(addr.address)
                hideSearchResults()
            }
        )

        rvSearchResults?.layoutManager = androidx.recyclerview.widget.LinearLayoutManager(this)
        rvSearchResults?.adapter = searchResultsAdapter

        etGlobalSearch?.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                val query = s?.toString() ?: ""
                performDebouncedSearch(query)
            }
            override fun afterTextChanged(s: android.text.Editable?) {}
        })

        tvCloseSearch?.setOnClickListener {
            etGlobalSearch?.text?.clear()
            hideSearchResults()
        }
    }

    private fun performDebouncedSearch(query: String) {
        searchJob?.cancel()
        val trimmed = query.trim()
        if (trimmed.isEmpty()) {
            hideSearchResults()
            return
        }

        searchJob = lifecycleScope.launch {
            kotlinx.coroutines.delay(300)

            val progressJob = launch {
                kotlinx.coroutines.delay(200)
                pbSearchLoading?.visibility = View.VISIBLE
            }

            try {
                val results = SearchEngine.search(
                    query = trimmed,
                    functions = allFunctionsCached,
                    strings = allStringsCached,
                    disassembly = allDisassemblyCached
                )

                progressJob.cancel()
                pbSearchLoading?.visibility = View.GONE

                searchResultsAdapter.submitResults(results, trimmed)
                cardSearchResults?.visibility = View.VISIBLE
            } catch (e: Exception) {
                progressJob.cancel()
                pbSearchLoading?.visibility = View.GONE
                e.printStackTrace()
            }
        }
    }

    private fun hideSearchResults() {
        cardSearchResults?.visibility = View.GONE
    }

    private fun navigateToStringAddress(address: Long) {
        if (resources.configuration.orientation != Configuration.ORIENTATION_LANDSCAPE) {
            viewPager.currentItem = 0
        }
        scrollToStringsAddress(address)
    }

    private fun scrollToStringsAddress(address: Long) {
        val index = allStringsCached.indexOfFirst {
            val itemOffsetLong = it.offset.removePrefix("0x").toLongOrNull(16)
            itemOffsetLong == address
        }
        if (index != -1) {
            val recyclerView = tabRecyclerViews[0]
            val layoutManager = recyclerView?.layoutManager as? androidx.recyclerview.widget.LinearLayoutManager
            layoutManager?.scrollToPositionWithOffset(index, 0)
        }
    }

    private fun showAnnotationDialog(address: Long, defaultName: String) {
        val annotation = AnnotationRepository.getAnnotation(address)
        val currentCustomName = annotation?.customName ?: ""
        val currentComment = annotation?.comment ?: ""

        val dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_annotation, null)
        val tvTitle: TextView = dialogView.findViewById(R.id.tv_dialog_title)
        val etRename: EditText = dialogView.findViewById(R.id.et_rename)
        val etComment: EditText = dialogView.findViewById(R.id.et_comment)
        val btnXrefs: android.widget.Button = dialogView.findViewById(R.id.btn_xrefs)
        val btnCancel: android.widget.Button = dialogView.findViewById(R.id.btn_cancel)
        val btnSave: android.widget.Button = dialogView.findViewById(R.id.btn_save)

        tvTitle.text = "ANNOTATE ADDRESS: 0x${address.toString(16).uppercase()}"
        etRename.setText(currentCustomName.ifEmpty { defaultName })
        etComment.setText(currentComment)

        val dialog = androidx.appcompat.app.AlertDialog.Builder(this)
            .setView(dialogView)
            .create()

        btnXrefs.setOnClickListener {
            dialog.dismiss()
            showXrefDialog(address, defaultName)
        }

        btnCancel.setOnClickListener {
            dialog.dismiss()
        }

        btnSave.setOnClickListener {
            val customName = etRename.text.toString().trim()
            val comment = etComment.text.toString().trim()

            val savedName = if (customName.isNotEmpty() && customName != defaultName) customName else null
            val savedComment = if (comment.isNotEmpty()) comment else null

            if (savedName == null && savedComment == null) {
                AnnotationRepository.deleteAnnotation(this, currentFileName, address)
            } else {
                AnnotationRepository.upsertAnnotation(this, currentFileName, address, savedName, savedComment)
            }

            dialog.dismiss()
            refreshVisibleAdapters()
        }

        dialog.show()
        dialog.window?.setBackgroundDrawableResource(android.R.color.transparent)
    }

    private fun refreshVisibleAdapters() {
        functionsAdapter.notifyDataSetChanged()
        disassemblyTabAdapter.notifyDataSetChanged()
    }

    override fun onCreateOptionsMenu(menu: android.view.Menu?): Boolean {
        menu?.add(0, 102, 0, "Export Analysis Report")?.apply {
            setShowAsAction(android.view.MenuItem.SHOW_AS_ACTION_ALWAYS)
            setIcon(android.R.drawable.ic_menu_share)
        }
        menu?.add(0, 101, 1, "Clear Extracted Cache")?.apply {
            setShowAsAction(android.view.MenuItem.SHOW_AS_ACTION_NEVER)
        }
        return true
    }

    override fun onOptionsItemSelected(item: android.view.MenuItem): Boolean {
        if (item.itemId == 101) {
            lifecycleScope.launch(Dispatchers.IO) {
                ApkInspector.clearCache(this@MainActivity, maxAgeDays = 0)
                withContext(Dispatchers.Main) {
                    android.widget.Toast.makeText(this@MainActivity, "Extracted libraries cache cleared", android.widget.Toast.LENGTH_SHORT).show()
                }
            }
            return true
        }
        if (item.itemId == 102) {
            showExportDialog()
            return true
        }
        return super.onOptionsItemSelected(item)
    }

    private fun showExportDialog() {
        if (binaryBuffer == null || currentFileName.isEmpty()) {
            android.widget.Toast.makeText(this, "Please load a binary first before exporting!", android.widget.Toast.LENGTH_SHORT).show()
            return
        }

        val context = this
        val container = android.widget.LinearLayout(context).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            val pad = (20 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad, pad, pad)
            setBackgroundColor(getColor(R.color.dark_surface))
        }

        val tvDesc = TextView(context).apply {
            text = "Select format and sections to generate a detailed static analysis report. Note that disassembly is generated on-the-fly and can be extremely large."
            setTextColor(getColor(R.color.text_secondary))
            textSize = 14f
            setPadding(0, 0, 0, (16 * resources.displayMetrics.density).toInt())
        }
        container.addView(tvDesc)

        val tvFormatTitle = TextView(context).apply {
            text = "EXPORT FORMAT"
            setTypeface(null, android.graphics.Typeface.BOLD)
            textSize = 13f
            setTextColor(getColor(R.color.neon_pink))
            setPadding(0, 0, 0, (6 * resources.displayMetrics.density).toInt())
        }
        container.addView(tvFormatTitle)

        val rgFormat = android.widget.RadioGroup(context).apply {
            orientation = android.widget.RadioGroup.HORIZONTAL
            setPadding(0, 0, 0, (18 * resources.displayMetrics.density).toInt())
        }
        val rbJson = android.widget.RadioButton(context).apply {
            text = "JSON Format"
            setTextColor(getColor(R.color.text_primary))
            buttonTintList = android.content.res.ColorStateList.valueOf(getColor(R.color.neon_pink))
            id = View.generateViewId()
            isChecked = true
        }
        val rbText = android.widget.RadioButton(context).apply {
            text = "IDA Plain Text"
            setTextColor(getColor(R.color.text_primary))
            buttonTintList = android.content.res.ColorStateList.valueOf(getColor(R.color.neon_pink))
            id = View.generateViewId()
        }
        rgFormat.addView(rbJson)
        rgFormat.addView(rbText)
        container.addView(rgFormat)

        val tvSectionsTitle = TextView(context).apply {
            text = "REPORT SECTIONS"
            setTypeface(null, android.graphics.Typeface.BOLD)
            textSize = 13f
            setTextColor(getColor(R.color.neon_pink))
            setPadding(0, 0, 0, (6 * resources.displayMetrics.density).toInt())
        }
        container.addView(tvSectionsTitle)

        val cbHeader = android.widget.CheckBox(context).apply {
            text = "Header Information"
            setTextColor(getColor(R.color.text_primary))
            buttonTintList = android.content.res.ColorStateList.valueOf(getColor(R.color.neon_cyan))
            isChecked = true
        }
        val cbSymbols = android.widget.CheckBox(context).apply {
            text = "Symbols / Function Table"
            setTextColor(getColor(R.color.text_primary))
            buttonTintList = android.content.res.ColorStateList.valueOf(getColor(R.color.neon_cyan))
            isChecked = true
        }
        val cbStrings = android.widget.CheckBox(context).apply {
            text = "Printable Strings"
            setTextColor(getColor(R.color.text_primary))
            buttonTintList = android.content.res.ColorStateList.valueOf(getColor(R.color.neon_cyan))
            isChecked = true
        }
        val cbXrefs = android.widget.CheckBox(context).apply {
            text = "Cross-References (XREFs)"
            setTextColor(getColor(R.color.text_primary))
            buttonTintList = android.content.res.ColorStateList.valueOf(getColor(R.color.neon_cyan))
            isChecked = true
        }
        val cbAnnotations = android.widget.CheckBox(context).apply {
            text = "Annotations & Comments"
            setTextColor(getColor(R.color.text_primary))
            buttonTintList = android.content.res.ColorStateList.valueOf(getColor(R.color.neon_cyan))
            isChecked = true
        }
        val cbDisassembly = android.widget.CheckBox(context).apply {
            text = "Full Disassembly (.text)"
            setTextColor(getColor(R.color.text_primary))
            buttonTintList = android.content.res.ColorStateList.valueOf(getColor(R.color.neon_cyan))
            isChecked = false
        }

        container.addView(cbHeader)
        container.addView(cbSymbols)
        container.addView(cbStrings)
        container.addView(cbXrefs)
        container.addView(cbAnnotations)
        container.addView(cbDisassembly)

        val tvWarning = TextView(context).apply {
            text = "⚠️ Warning: Generating full disassembly for large binaries (up to 300MB) can take a while and produce very large files."
            setTextColor(getColor(R.color.neon_pink))
            textSize = 12f
            visibility = View.GONE
            setPadding(0, (12 * resources.displayMetrics.density).toInt(), 0, 0)
        }
        container.addView(tvWarning)

        cbDisassembly.setOnCheckedChangeListener { _, isChecked ->
            tvWarning.visibility = if (isChecked) View.VISIBLE else View.GONE
        }

        val scrollView = android.widget.ScrollView(context).apply {
            addView(container)
        }

        val dialog = androidx.appcompat.app.AlertDialog.Builder(context)
            .setTitle("EXPORT ANALYSIS REPORT")
            .setView(scrollView)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Export") { _, _ ->
                exportFormatSelected = if (rbJson.isChecked) ExportFormat.JSON else ExportFormat.TEXT
                
                val sections = mutableSetOf<ExportSection>()
                if (cbHeader.isChecked) sections.add(ExportSection.HEADER)
                if (cbSymbols.isChecked) sections.add(ExportSection.SYMBOLS)
                if (cbStrings.isChecked) sections.add(ExportSection.STRINGS)
                if (cbXrefs.isChecked) sections.add(ExportSection.XREFS)
                if (cbAnnotations.isChecked) sections.add(ExportSection.ANNOTATIONS)
                if (cbDisassembly.isChecked) sections.add(ExportSection.DISASSEMBLY)

                exportSectionsSelected = sections

                val defaultName = if (exportFormatSelected == ExportFormat.JSON) {
                    "${currentFileName.substringBeforeLast(".")}_analysis.json"
                } else {
                    "${currentFileName.substringBeforeLast(".")}_analysis.txt"
                }
                createDocumentLauncher.launch(defaultName)
            }
            .create()

        dialog.show()
    }

    private fun performExport(uri: Uri) {
        val progressView = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            val pad = (20 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad, pad, pad)
            setBackgroundColor(getColor(R.color.dark_surface))
        }
        val tvProgressSection = TextView(this).apply {
            text = "Starting report export..."
            textSize = 15f
            setTypeface(null, android.graphics.Typeface.BOLD)
            setTextColor(getColor(R.color.text_primary))
            setPadding(0, 0, 0, (8 * resources.displayMetrics.density).toInt())
        }
        val tvProgressDetails = TextView(this).apply {
            text = "Preparing buffers..."
            textSize = 13f
            setTextColor(getColor(R.color.text_secondary))
            setPadding(0, 0, 0, (12 * resources.displayMetrics.density).toInt())
        }
        val progressBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            isIndeterminate = true
            max = 100
        }
        progressView.addView(tvProgressSection)
        progressView.addView(tvProgressDetails)
        progressView.addView(progressBar)

        var exportJob: kotlinx.coroutines.Job? = null

        val progressDialog = androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Exporting Analysis")
            .setView(progressView)
            .setCancelable(false)
            .setNegativeButton("Cancel") { _, _ ->
                exportJob?.cancel()
            }
            .create()

        progressDialog.show()

        lifecycleScope.launch(Dispatchers.Main) {
            exportJob = coroutineContext[kotlinx.coroutines.Job]
            
            val result = ExportManager.exportReport(
                fileId = currentFileName,
                context = this@MainActivity,
                format = exportFormatSelected,
                sections = exportSectionsSelected,
                outputUri = uri,
                binaryBuffer = binaryBuffer,
                elfHeader = elfHeaderCached,
                onProgress = { progress ->
                    lifecycleScope.launch(Dispatchers.Main) {
                        val sectionName = when (progress.section) {
                            ExportSection.HEADER -> "ELF Header"
                            ExportSection.SYMBOLS -> "Symbols Table"
                            ExportSection.STRINGS -> "Printable Strings"
                            ExportSection.XREFS -> "Cross-References (XREFs)"
                            ExportSection.ANNOTATIONS -> "Annotations & Comments"
                            ExportSection.DISASSEMBLY -> "Disassembly"
                        }
                        tvProgressSection.text = "Exporting: $sectionName"
                        if (progress.estimatedTotal != null && progress.estimatedTotal > 0) {
                            progressBar.isIndeterminate = false
                            progressBar.max = progress.estimatedTotal
                            progressBar.progress = progress.itemsWritten
                            val pct = (progress.itemsWritten * 100) / progress.estimatedTotal
                            tvProgressDetails.text = "Written ${progress.itemsWritten} of ${progress.estimatedTotal} items ($pct%)"
                        } else {
                            progressBar.isIndeterminate = true
                            tvProgressDetails.text = "Written ${progress.itemsWritten} items (streaming...)"
                        }
                    }
                }
            )

            progressDialog.dismiss()

            result.onSuccess {
                android.widget.Toast.makeText(this@MainActivity, "Report successfully exported!", android.widget.Toast.LENGTH_LONG).show()
            }.onFailure { e ->
                if (e is kotlinx.coroutines.CancellationException) {
                    android.widget.Toast.makeText(this@MainActivity, "Export cancelled.", android.widget.Toast.LENGTH_SHORT).show()
                } else {
                    android.widget.Toast.makeText(this@MainActivity, "Export failed: ${e.message}", android.widget.Toast.LENGTH_LONG).show()
                }
            }
        }
    }
}

// --- VIEW PAGER 2 ADAPTER ---

class TabPagerAdapter(
    private val stringsAdapter: StringsAdapter,
    private val functionsAdapter: FunctionsAdapter,
    private val hexAdapter: HexAdapter,
    private val disassemblyTabAdapter: DisassemblyTabAdapter,
    private val onInitTab: (position: Int, itemView: View, recyclerView: RecyclerView, progress: ProgressBar, emptyState: View) -> Unit
) : RecyclerView.Adapter<TabPagerAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val recyclerView: RecyclerView = view.findViewById(R.id.recycler_view)
        val progress: ProgressBar = view.findViewById(R.id.loading_indicator)
        val emptyState: View = view.findViewById(R.id.empty_state)
    }

    override fun getItemCount(): Int = 4

    override fun getItemViewType(position: Int): Int {
        return position
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val layoutId = if (viewType == 3) R.layout.tab_disassembly else R.layout.tab_recycler
        val view = LayoutInflater.from(parent.context).inflate(layoutId, parent, false)
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
            3 -> holder.recyclerView.adapter = disassemblyTabAdapter
        }
        onInitTab(position, holder.itemView, holder.recyclerView, holder.progress, holder.emptyState)
    }
}

