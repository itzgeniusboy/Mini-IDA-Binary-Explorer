package com.example

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView

// --- STRINGS ADAPTER ---

class StringsAdapter : ListAdapter<ElfParser.ElfString, StringsAdapter.ViewHolder>(DiffCallback) {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvOffset: TextView = view.findViewById(R.id.tv_string_offset)
        val tvLen: TextView = view.findViewById(R.id.tv_string_len)
        val tvValue: TextView = view.findViewById(R.id.tv_string_value)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_string, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)
        holder.tvOffset.text = item.offset
        holder.tvLen.text = "LEN: ${item.length}"
        holder.tvValue.text = item.value
    }

    companion object DiffCallback : DiffUtil.ItemCallback<ElfParser.ElfString>() {
        override fun areItemsTheSame(oldItem: ElfParser.ElfString, newItem: ElfParser.ElfString): Boolean {
            return oldItem.offset == newItem.offset
        }
        override fun areContentsTheSame(oldItem: ElfParser.ElfString, newItem: ElfParser.ElfString): Boolean {
            return oldItem == newItem
        }
    }
}

// --- FUNCTIONS ADAPTER ---

class FunctionsAdapter(
    private val onItemClick: ((ElfParser.ElfFunction) -> Unit)? = null,
    private val onItemLongClick: ((ElfParser.ElfFunction) -> Boolean)? = null
) : ListAdapter<ElfParser.ElfFunction, FunctionsAdapter.ViewHolder>(DiffCallback) {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvAddress: TextView = view.findViewById(R.id.tv_func_address)
        val tvMeta: TextView = view.findViewById(R.id.tv_func_meta)
        val tvName: TextView = view.findViewById(R.id.tv_func_name)
        val tvSize: TextView = view.findViewById(R.id.tv_func_size)
        val tvIndex: TextView = view.findViewById(R.id.tv_func_index)
        val tvCommentIndicator: TextView = view.findViewById(R.id.tv_func_comment_indicator)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_function, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)
        holder.tvAddress.text = item.address
        holder.tvMeta.text = "${item.type} [${item.bind}]"
        
        val cleanAddr = item.address.removePrefix("0x")
        val addressLong = cleanAddr.toLongOrNull(16) ?: 0L
        
        holder.tvName.text = AnnotationRepository.resolveName(addressLong, item.name)
        
        val annotation = AnnotationRepository.getAnnotation(addressLong)
        if (annotation != null && !annotation.comment.isNullOrBlank()) {
            holder.tvCommentIndicator.visibility = View.VISIBLE
        } else {
            holder.tvCommentIndicator.visibility = View.GONE
        }
        
        holder.tvSize.text = "SIZE: ${item.size}"
        holder.tvIndex.text = "SYM #${item.index}"
        
        holder.itemView.setOnClickListener {
            onItemClick?.invoke(item)
        }
        holder.itemView.setOnLongClickListener {
            onItemLongClick?.invoke(item) ?: false
        }
    }

    companion object DiffCallback : DiffUtil.ItemCallback<ElfParser.ElfFunction>() {
        override fun areItemsTheSame(oldItem: ElfParser.ElfFunction, newItem: ElfParser.ElfFunction): Boolean {
            return oldItem.address == newItem.address
        }
        override fun areContentsTheSame(oldItem: ElfParser.ElfFunction, newItem: ElfParser.ElfFunction): Boolean {
            return oldItem == newItem
        }
    }
}

// --- HEX DUMP ADAPTER ---

class HexAdapter : ListAdapter<ElfParser.HexRow, HexAdapter.ViewHolder>(DiffCallback) {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvAddress: TextView = view.findViewById(R.id.tv_hex_address)
        val tvBytes: TextView = view.findViewById(R.id.tv_hex_bytes)
        val tvAscii: TextView = view.findViewById(R.id.tv_hex_ascii)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_hex, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)
        holder.tvAddress.text = "${item.address}:"
        holder.tvBytes.text = item.hexBytes
        holder.tvAscii.text = "⎾${item.ascii}⏌"
    }

    companion object DiffCallback : DiffUtil.ItemCallback<ElfParser.HexRow>() {
        override fun areItemsTheSame(oldItem: ElfParser.HexRow, newItem: ElfParser.HexRow): Boolean {
            return oldItem.address == newItem.address
        }
        override fun areContentsTheSame(oldItem: ElfParser.HexRow, newItem: ElfParser.HexRow): Boolean {
            return oldItem == newItem
        }
    }
}

// --- DISASSEMBLY ADAPTER ---

class DisassemblyAdapter : ListAdapter<String, DisassemblyAdapter.ViewHolder>(DiffCallback) {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvLineText: TextView = view.findViewById(R.id.tv_line_text)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_hex_disassembly_line, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)
        holder.tvLineText.text = item
        
        // Apply micro-highlights for optimized, high-fidelity visual scanning
        val trimmed = item.trim()
        when {
            trimmed.startsWith("void ") || trimmed.startsWith("if ") || trimmed.startsWith("return;") || trimmed.startsWith("goto ") -> {
                holder.tvLineText.setTextColor(android.graphics.Color.parseColor("#00E5FF")) // Neon Cyan
            }
            trimmed.startsWith("x") || trimmed.startsWith("w") || trimmed.startsWith("*") -> {
                holder.tvLineText.setTextColor(android.graphics.Color.parseColor("#FF007F")) // Neon Pink
            }
            trimmed.startsWith("[") -> {
                holder.tvLineText.setTextColor(android.graphics.Color.parseColor("#00FF66")) // Neon Green
            }
            else -> {
                holder.tvLineText.setTextColor(android.graphics.Color.parseColor("#FFFFFF")) // Clean White
            }
        }
    }

    companion object DiffCallback : DiffUtil.ItemCallback<String>() {
        override fun areItemsTheSame(oldItem: String, newItem: String): Boolean {
            return oldItem == newItem
        }
        override fun areContentsTheSame(oldItem: String, newItem: String): Boolean {
            return oldItem == newItem
        }
    }
}

// --- PORTRAIT DISASSEMBLY TAB ADAPTER ---

class DisassemblyTabAdapter(
    private val onItemClick: ((DisassemblyLine) -> Unit)? = null,
    private val onItemLongClick: ((DisassemblyLine) -> Boolean)? = null
) : ListAdapter<DisassemblyLine, DisassemblyTabAdapter.ViewHolder>(DiffCallback) {

    private var highlightAddress: Long? = null

    fun setHighlightAddress(address: Long?) {
        val oldHighlight = highlightAddress
        highlightAddress = address
        
        // Find indices to notify
        for (i in 0 until itemCount) {
            val item = getItem(i)
            if (item.address == oldHighlight || item.address == address) {
                notifyItemChanged(i)
            }
        }
    }

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvLineText: TextView = view.findViewById(R.id.tv_line_text)
        val tvCommentText: TextView = view.findViewById(R.id.tv_comment_text)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_hex_disassembly_line, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)
        
        val resolvedLabel = AnnotationRepository.resolveAddressName(item.address)
        val addrStr = "0x" + item.address.toString(16).uppercase().padStart(8, '0')
        val formatted = if (resolvedLabel != "sub_${item.address.toString(16).uppercase()}") {
            "$addrStr <$resolvedLabel>:  ${item.bytesHex.padEnd(16)}  ${item.mnemonic.padEnd(8)} ${item.opStr}"
        } else {
            "$addrStr:  ${item.bytesHex.padEnd(16)}  ${item.mnemonic.padEnd(8)} ${item.opStr}"
        }
        holder.tvLineText.text = formatted

        // Handle inline comments
        val annotation = AnnotationRepository.getAnnotation(item.address)
        if (annotation != null && !annotation.comment.isNullOrBlank()) {
            holder.tvCommentText.text = "; ${annotation.comment}"
            holder.tvCommentText.visibility = View.VISIBLE
        } else {
            val targetAddr = XrefAnalyzer.extractTargetAddress(item.opStr)
            val resolvedTarget = if (targetAddr != null) AnnotationRepository.resolveAddressName(targetAddr) else null
            if (targetAddr != null && resolvedTarget != null && resolvedTarget != "sub_${targetAddr.toString(16).uppercase()}") {
                holder.tvCommentText.text = "; $resolvedTarget"
                holder.tvCommentText.visibility = View.VISIBLE
            } else {
                holder.tvCommentText.visibility = View.GONE
            }
        }

        holder.itemView.setOnClickListener {
            onItemClick?.invoke(item)
        }
        holder.itemView.setOnLongClickListener {
            onItemLongClick?.invoke(item) ?: false
        }

        if (item.address == highlightAddress) {
            holder.itemView.setBackgroundColor(android.graphics.Color.parseColor("#3300FF66")) // 20% alpha neon green
        } else {
            holder.itemView.setBackgroundColor(android.graphics.Color.TRANSPARENT)
        }

        when (item.mnemonic.lowercase()) {
            "cmp", "tst" -> holder.tvLineText.setTextColor(android.graphics.Color.parseColor("#FF007F")) // Neon Pink
            "b", "bl", "beq", "bne", "b.eq", "b.ne", "b.ge", "b.lt", "b.gt", "b.le", "jmp", "je", "jne" -> holder.tvLineText.setTextColor(android.graphics.Color.parseColor("#00E5FF")) // Neon Cyan
            "ldr", "str", "mov" -> holder.tvLineText.setTextColor(android.graphics.Color.parseColor("#00FF66")) // Neon Green
            "add", "sub", "mul", "div" -> holder.tvLineText.setTextColor(android.graphics.Color.parseColor("#FFD700")) // Gold
            "ret" -> holder.tvLineText.setTextColor(android.graphics.Color.parseColor("#FF3333")) // Red
            else -> holder.tvLineText.setTextColor(android.graphics.Color.parseColor("#FFFFFF")) // Clean White
        }
    }

    companion object DiffCallback : DiffUtil.ItemCallback<DisassemblyLine>() {
        override fun areItemsTheSame(oldItem: DisassemblyLine, newItem: DisassemblyLine): Boolean {
            return oldItem.address == newItem.address
        }
        override fun areContentsTheSame(oldItem: DisassemblyLine, newItem: DisassemblyLine): Boolean {
            return oldItem == newItem
        }
    }
}

sealed class SearchRow {
    data class Header(val title: String) : SearchRow()
    data class Address(val addressResult: AddressResult) : SearchRow()
    data class Symbol(val symbolResult: SymbolResult) : SearchRow()
    data class StringRow(val stringResult: StringResult) : SearchRow()
    data class NoResults(val query: String) : SearchRow()
}

class SearchResultsAdapter(
    private val onSymbolClick: (SymbolResult) -> Unit,
    private val onStringClick: (StringResult) -> Unit,
    private val onAddressClick: (AddressResult) -> Unit
) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {

    private var items: List<SearchRow> = emptyList()

    fun submitResults(results: SearchResults, query: String) {
        val list = mutableListOf<SearchRow>()

        if (results.address != null) {
            list.add(SearchRow.Header("DIRECT ADDRESS JUMP"))
            list.add(SearchRow.Address(results.address))
        }

        if (results.symbols.isNotEmpty()) {
            list.add(SearchRow.Header("FUNCTIONS / SYMBOLS (${results.symbols.size})"))
            for (sym in results.symbols) {
                list.add(SearchRow.Symbol(sym))
            }
        }

        if (results.strings.isNotEmpty()) {
            list.add(SearchRow.Header("STRINGS (${results.strings.size})"))
            for (str in results.strings) {
                list.add(SearchRow.StringRow(str))
            }
        }

        if (list.isEmpty() && query.isNotEmpty()) {
            list.add(SearchRow.NoResults(query))
        }

        items = list
        notifyDataSetChanged()
    }

    override fun getItemViewType(position: Int): Int {
        return when (items[position]) {
            is SearchRow.Header -> 0
            is SearchRow.Address -> 1
            is SearchRow.Symbol -> 2
            is SearchRow.StringRow -> 3
            is SearchRow.NoResults -> 4
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        val inflater = LayoutInflater.from(parent.context)
        return when (viewType) {
            0 -> {
                val view = inflater.inflate(android.R.layout.simple_list_item_1, parent, false)
                HeaderViewHolder(view)
            }
            1 -> {
                val view = inflater.inflate(R.layout.item_xref_list, parent, false)
                AddressViewHolder(view)
            }
            2 -> {
                val view = inflater.inflate(R.layout.item_xref_list, parent, false)
                SymbolViewHolder(view)
            }
            3 -> {
                val view = inflater.inflate(R.layout.item_xref_list, parent, false)
                StringViewHolder(view)
            }
            else -> {
                val view = inflater.inflate(android.R.layout.simple_list_item_1, parent, false)
                NoResultsViewHolder(view)
            }
        }
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        when (val item = items[position]) {
            is SearchRow.Header -> {
                val h = holder as HeaderViewHolder
                h.textView.text = item.title
                h.textView.setTextColor(android.graphics.Color.parseColor("#94A3B8")) // text_secondary
                h.textView.textSize = 10f
                h.textView.paint.isFakeBoldText = true
                h.textView.setPadding(16, 12, 16, 4)
            }
            is SearchRow.Address -> {
                val h = holder as AddressViewHolder
                val addrHex = "0x" + item.addressResult.address.toString(16).uppercase()
                h.tvText.text = "GO TO $addrHex (Disassembly)"
                h.tvText.setTextColor(android.graphics.Color.parseColor("#00FF66")) // neon_green
                h.itemView.setOnClickListener { onAddressClick(item.addressResult) }
            }
            is SearchRow.Symbol -> {
                val h = holder as SymbolViewHolder
                val addrHex = "0x" + item.symbolResult.address.toString(16).uppercase()
                h.tvText.text = "$addrHex: ${item.symbolResult.name}"
                h.tvText.setTextColor(android.graphics.Color.parseColor("#00E5FF")) // neon_cyan
                h.itemView.setOnClickListener { onSymbolClick(item.symbolResult) }
            }
            is SearchRow.StringRow -> {
                val h = holder as StringViewHolder
                val addrHex = "0x" + item.stringResult.address.toString(16).uppercase()
                h.tvText.text = "$addrHex: \"${item.stringResult.text}\""
                h.tvText.setTextColor(android.graphics.Color.parseColor("#FF007F")) // neon_pink
                h.itemView.setOnClickListener { onStringClick(item.stringResult) }
            }
            is SearchRow.NoResults -> {
                val h = holder as NoResultsViewHolder
                h.textView.text = "No results found for: \"${item.query}\""
                h.textView.setTextColor(android.graphics.Color.parseColor("#FF007F")) // neon_pink
                h.textView.textSize = 12f
                h.textView.setPadding(16, 16, 16, 16)
            }
        }
    }

    override fun getItemCount(): Int = items.size

    class HeaderViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val textView: TextView = view.findViewById(android.R.id.text1)
    }

    class AddressViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvText: TextView = view.findViewById(R.id.tv_xref_text)
    }

    class SymbolViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvText: TextView = view.findViewById(R.id.tv_xref_text)
    }

    class StringViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvText: TextView = view.findViewById(R.id.tv_xref_text)
    }

    class NoResultsViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val textView: TextView = view.findViewById(android.R.id.text1)
    }
}



