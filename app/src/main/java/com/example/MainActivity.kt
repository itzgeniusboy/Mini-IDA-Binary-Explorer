package com.example

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
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

class MainActivity : AppCompatActivity() {

    private lateinit var tvFilePath: TextView
    private lateinit var btnPickFile: MaterialButton
    private lateinit var statusBadge: TextView
    private lateinit var infoPanelCard: CardView
    
    // ELF Header UI views
    private lateinit var tvElfClass: TextView
    private lateinit var tvElfMachine: TextView
    private lateinit var tvElfEntry: TextView
    private lateinit var tvElfEndian: TextView

    private lateinit var tabLayout: TabLayout
    private lateinit var viewPager: ViewPager2

    // Highly optimized adapters
    private val stringsAdapter = StringsAdapter()
    private val functionsAdapter = FunctionsAdapter()
    private val hexAdapter = HexAdapter()

    // References to the UI widgets inside the view pager tabs
    private val tabRecyclerViews = mutableMapOf<Int, RecyclerView>()
    private val tabProgressBars = mutableMapOf<Int, ProgressBar>()
    private val tabEmptyStates = mutableMapOf<Int, View>()

    // Selected file data cached
    private var binaryBuffer: java.nio.ByteBuffer? = null
    private lateinit var offsetsDbHelper: OffsetsDatabaseHelper

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
        setContentView(R.layout.activity_main)

        // Request POST_NOTIFICATIONS runtime permission on Android 13+ (API 33+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        // Initialize views
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

        // Hook up the button trigger
        btnPickFile.setOnClickListener {
            filePickerLauncher.launch("*/*")
        }

        // Initialize offsets database helper
        offsetsDbHelper = OffsetsDatabaseHelper(this)

        setupViewPager()
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

            // Sync with current data if loaded already
            updateTabPlaceholderState(position)
        }

        viewPager.adapter = pagerAdapter
        // Keep all 3 views cached to prevent tearing during swipe
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
        tvFilePath.text = displayName

        // Show loading spinner on active tabs
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

                    val strings = parser.extractStrings()
                    val functions = parser.parseSymbols()
                    val hexDump = parser.getHexDump()

                    // Populate database with the parsed symbols for this file
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
                            // Non-ELF file loaded (e.g. text or other binary)
                            infoPanelCard.visibility = View.VISIBLE
                            tvElfClass.text = "RAW DATA (Non-ELF)"
                            tvElfMachine.text = "N/A"
                            tvElfEntry.text = "0x0"
                            tvElfEndian.text = "System Default"
                        }

                        // Submit lists to optimized diff adapters
                        stringsAdapter.submitList(strings)
                        functionsAdapter.submitList(functions)
                        hexAdapter.submitList(hexDump)

                        // Hide progress bars and empty states
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

    private fun updateTabPlaceholderState(position: Int) {
        val buffer = binaryBuffer
        if (buffer == null) {
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
            // Fallback to filename extraction from path
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
