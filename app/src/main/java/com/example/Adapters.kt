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

class FunctionsAdapter(private val onItemClick: ((ElfParser.ElfFunction) -> Unit)? = null) : ListAdapter<ElfParser.ElfFunction, FunctionsAdapter.ViewHolder>(DiffCallback) {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvAddress: TextView = view.findViewById(R.id.tv_func_address)
        val tvMeta: TextView = view.findViewById(R.id.tv_func_meta)
        val tvName: TextView = view.findViewById(R.id.tv_func_name)
        val tvSize: TextView = view.findViewById(R.id.tv_func_size)
        val tvIndex: TextView = view.findViewById(R.id.tv_func_index)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_function, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)
        holder.tvAddress.text = item.address
        holder.tvMeta.text = "${item.type} [${item.bind}]"
        holder.tvName.text = item.name
        holder.tvSize.text = "SIZE: ${item.size}"
        holder.tvIndex.text = "SYM #${item.index}"
        
        holder.itemView.setOnClickListener {
            onItemClick?.invoke(item)
        }
    }

    companion object DiffCallback : DiffUtil.ItemCallback<ElfParser.ElfFunction>() {
        override fun areItemsTheSame(oldItem: ElfParser.ElfFunction, newItem: ElfParser.ElfFunction): Boolean {
            return oldItem.address == newItem.address && oldItem.name == newItem.name
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

