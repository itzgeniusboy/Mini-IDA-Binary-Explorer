package com.example

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.ImageView
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.text.style.ClickableSpan
import android.text.style.BackgroundColorSpan
import android.text.method.LinkMovementMethod
import android.text.TextPaint
import android.graphics.Typeface
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView

// --- STRINGS ADAPTER ---

class StringsAdapter : ListAdapter<ElfParser.ElfString, StringsAdapter.ViewHolder>(DiffCallback) {

    var getXrefCount: ((Long) -> Int)? = null
    var onXrefClick: ((ElfParser.ElfString) -> Unit)? = null
    var onBookmarkToggle: ((ElfParser.ElfString) -> Unit)? = null

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvOffset: TextView = view.findViewById(R.id.tv_string_offset)
        val tvLen: TextView = view.findViewById(R.id.tv_string_len)
        val tvValue: TextView = view.findViewById(R.id.tv_string_value)
        val tvXrefCount: TextView = view.findViewById(R.id.tv_string_xref_count)
        val ivBookmark: ImageView = view.findViewById(R.id.iv_string_bookmark)
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

        val addressVal = item.offset.removePrefix("0x").toLongOrNull(16) ?: 0L
        val count = getXrefCount?.invoke(addressVal) ?: 0
        if (count > 0) {
            holder.tvXrefCount.text = "referenced by $count function(s)"
            holder.tvXrefCount.visibility = View.VISIBLE
            val clickListener = View.OnClickListener {
                onXrefClick?.invoke(item)
            }
            holder.tvXrefCount.setOnClickListener(clickListener)
            holder.itemView.setOnClickListener(clickListener)
        } else {
            holder.tvXrefCount.visibility = View.GONE
            holder.itemView.setOnClickListener(null)
        }

        val isBookmarked = BookmarkRepository.isBookmarked(addressVal)
        if (isBookmarked) {
            holder.ivBookmark.setImageResource(android.R.drawable.btn_star_big_on)
        } else {
            holder.ivBookmark.setImageResource(android.R.drawable.btn_star_big_off)
        }
        holder.ivBookmark.setOnClickListener {
            onBookmarkToggle?.invoke(item)
        }

        // Alternating Card backgrounds for polished visual scanning
        (holder.itemView as? androidx.cardview.widget.CardView)?.setCardBackgroundColor(
            android.content.res.ColorStateList.valueOf(
                android.graphics.Color.parseColor(if (position % 2 == 0) "#121420" else "#1A1D2E")
            )
        )
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
    private val onItemLongClick: ((ElfParser.ElfFunction) -> Boolean)? = null,
    private val onAcceptSuggestion: ((ElfParser.ElfFunction, SignatureMatch) -> Unit)? = null,
    private val onDismissSuggestion: ((ElfParser.ElfFunction) -> Unit)? = null
) : ListAdapter<ElfParser.ElfFunction, FunctionsAdapter.ViewHolder>(DiffCallback) {

    var onBookmarkToggle: ((ElfParser.ElfFunction) -> Unit)? = null

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvAddress: TextView = view.findViewById(R.id.tv_func_address)
        val tvMeta: TextView = view.findViewById(R.id.tv_func_meta)
        val tvName: TextView = view.findViewById(R.id.tv_func_name)
        val tvSize: TextView = view.findViewById(R.id.tv_func_size)
        val tvIndex: TextView = view.findViewById(R.id.tv_func_index)
        val tvCommentIndicator: TextView = view.findViewById(R.id.tv_func_comment_indicator)
        val ivBookmark: ImageView = view.findViewById(R.id.iv_func_bookmark)
        val layoutSuggestionBadge: View = view.findViewById(R.id.layout_suggestion_badge)
        val tvSuggestionText: TextView = view.findViewById(R.id.tv_suggestion_text)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_function, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)
        if (item.address == "NOTICE") {
            holder.tvAddress.text = ""
            holder.tvMeta.text = ""
            holder.tvName.text = item.name
            holder.tvSize.text = ""
            holder.tvIndex.text = ""
            holder.tvCommentIndicator.visibility = View.GONE
            holder.ivBookmark.visibility = View.GONE
            holder.layoutSuggestionBadge.visibility = View.GONE
            holder.itemView.setOnClickListener(null)
            holder.itemView.setOnLongClickListener(null)
            (holder.itemView as? androidx.cardview.widget.CardView)?.setCardBackgroundColor(
                android.content.res.ColorStateList.valueOf(android.graphics.Color.parseColor("#121420"))
            )
            return
        }

        holder.ivBookmark.visibility = View.VISIBLE
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
        
        val isBookmarked = BookmarkRepository.isBookmarked(addressLong)
        if (isBookmarked) {
            holder.ivBookmark.setImageResource(android.R.drawable.btn_star_big_on)
        } else {
            holder.ivBookmark.setImageResource(android.R.drawable.btn_star_big_off)
        }
        holder.ivBookmark.setOnClickListener {
            onBookmarkToggle?.invoke(item)
        }

        // Show suggestion badge if we have a match and NO user custom name yet
        val suggestion = SignatureMatcher.getSuggestion(addressLong)
        if (suggestion != null && (annotation == null || annotation.customName.isNullOrBlank())) {
            holder.layoutSuggestionBadge.visibility = View.VISIBLE
            val confPercent = (suggestion.confidence * 100).toInt()
            holder.tvSuggestionText.text = "💡 Sug: ${suggestion.functionName} (${confPercent}%)"
            
            val badgeBg = android.graphics.drawable.GradientDrawable().apply {
                shape = android.graphics.drawable.GradientDrawable.RECTANGLE
                cornerRadius = 12f
                setColor(android.graphics.Color.parseColor("#142E2B"))
                setStroke(2, android.graphics.Color.parseColor("#00FFCC"))
            }
            holder.layoutSuggestionBadge.background = badgeBg
            
            holder.layoutSuggestionBadge.setOnClickListener {
                android.app.AlertDialog.Builder(holder.itemView.context, android.R.style.Theme_DeviceDefault_Dialog_Alert)
                    .setTitle("Signature Match Suggestion")
                    .setMessage("Auto-identified this function as '${suggestion.functionName}' with ${confPercent}% confidence from ${suggestion.signatureSource}.\n\nWould you like to accept this name suggestion?")
                    .setPositiveButton("Accept") { dialog, _ ->
                        onAcceptSuggestion?.invoke(item, suggestion)
                        dialog.dismiss()
                    }
                    .setNegativeButton("Dismiss") { dialog, _ ->
                        onDismissSuggestion?.invoke(item)
                        dialog.dismiss()
                    }
                    .setNeutralButton("Cancel") { dialog, _ ->
                        dialog.dismiss()
                    }
                    .show()
            }
        } else {
            holder.layoutSuggestionBadge.visibility = View.GONE
            holder.layoutSuggestionBadge.setOnClickListener(null)
        }

        holder.tvSize.text = "SIZE: ${item.size}"
        holder.tvIndex.text = "SYM #${item.index}"
        
        holder.itemView.setOnClickListener {
            onItemClick?.invoke(item)
        }
        holder.itemView.setOnLongClickListener {
            onItemLongClick?.invoke(item) ?: false
        }

        // Alternating Card backgrounds for polished visual scanning
        (holder.itemView as? androidx.cardview.widget.CardView)?.setCardBackgroundColor(
            android.content.res.ColorStateList.valueOf(
                android.graphics.Color.parseColor(if (position % 2 == 0) "#121420" else "#1A1D2E")
            )
        )
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

    var onByteClick: ((Long) -> Unit)? = null
    var highlightOffset: Long? = null
    var highlightLength: Int = 0

    private val handler = android.os.Handler(android.os.Looper.getMainLooper())
    private var clearHighlightRunnable: Runnable? = null

    fun setHighlightRange(offset: Long?, length: Int) {
        val oldOffset = highlightOffset
        val oldLength = highlightLength
        highlightOffset = offset
        highlightLength = length
        
        val startRow = if (oldOffset != null) (oldOffset / 16).toInt() else -1
        val endRow = if (oldOffset != null) ((oldOffset + oldLength - 1) / 16).toInt() else -1
        val newStartRow = if (offset != null) (offset / 16).toInt() else -1
        val newEndRow = if (offset != null) ((offset + length - 1) / 16).toInt() else -1
        
        val minRow = listOf(startRow, newStartRow).filter { it >= 0 }.minOrNull() ?: 0
        val maxRow = listOf(endRow, newEndRow).filter { it >= 0 }.maxOrNull() ?: (itemCount - 1)
        
        for (i in minRow..maxRow) {
            if (i in 0 until itemCount) {
                notifyItemChanged(i)
            }
        }
        
        clearHighlightRunnable?.let { handler.removeCallbacks(it) }
        
        if (offset != null) {
            val runnable = Runnable {
                val lastOffset = highlightOffset
                val lastLength = highlightLength
                highlightOffset = null
                highlightLength = 0
                val clearStart = if (lastOffset != null) (lastOffset / 16).toInt() else -1
                val clearEnd = if (lastOffset != null) ((lastOffset + lastLength - 1) / 16).toInt() else -1
                for (i in clearStart..clearEnd) {
                    if (i in 0 until itemCount) {
                        notifyItemChanged(i)
                    }
                }
            }
            clearHighlightRunnable = runnable
            handler.postDelayed(runnable, 1500)
        }
    }

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvAddress: TextView = view.findViewById(R.id.tv_hex_address)
        val tvBytes: TextView = view.findViewById(R.id.tv_hex_bytes)
        val tvAscii: TextView = view.findViewById(R.id.tv_hex_ascii)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_hex, parent, false)
        return ViewHolder(view)
    }

    @Suppress("RecyclerView")
    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)
        holder.tvAddress.text = "${item.address}:"
        
        val baseAddress = item.address.removePrefix("0x").toLongOrNull(16) ?: 0L

        // 1. Address Click
        holder.tvAddress.setOnClickListener {
            onByteClick?.invoke(baseAddress)
        }

        // 2. Ascii Click/Highlight
        val asciiBuilder = SpannableStringBuilder(item.ascii)
        for (i in 0 until item.ascii.length) {
            val byteOffset = baseAddress + i
            val hOffset = highlightOffset
            if (hOffset != null && byteOffset >= hOffset && byteOffset < hOffset + highlightLength) {
                asciiBuilder.setSpan(
                    BackgroundColorSpan(android.graphics.Color.parseColor("#FF007F")),
                    i,
                    i + 1,
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                )
                asciiBuilder.setSpan(
                    ForegroundColorSpan(android.graphics.Color.WHITE),
                    i,
                    i + 1,
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                )
            }
        }
        holder.tvAscii.text = SpannableStringBuilder("⎾").append(asciiBuilder).append("⏌")
        holder.tvAscii.setOnClickListener {
            onByteClick?.invoke(baseAddress)
        }

        // 3. Bytes Click with ClickableSpans
        val spannableBytes = SpannableStringBuilder()
        val bytesList = item.hexBytes.split(" ")
        var currentIdx = 0
        for (i in bytesList.indices) {
            val b = bytesList[i]
            if (b.isEmpty()) continue
            
            val start = currentIdx
            spannableBytes.append(b)
            val end = currentIdx + b.length
            val byteIndex = i
            
            val hOffset = highlightOffset
            if (hOffset != null && (baseAddress + byteIndex) >= hOffset && (baseAddress + byteIndex) < hOffset + highlightLength) {
                spannableBytes.setSpan(
                    BackgroundColorSpan(android.graphics.Color.parseColor("#FF007F")),
                    start,
                    end,
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                )
                spannableBytes.setSpan(
                    ForegroundColorSpan(android.graphics.Color.WHITE),
                    start,
                    end,
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                )
            }
            
            spannableBytes.setSpan(object : ClickableSpan() {
                override fun onClick(widget: View) {
                    onByteClick?.invoke(baseAddress + byteIndex)
                }
                override fun updateDrawState(ds: TextPaint) {
                    ds.isUnderlineText = false
                }
            }, start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            
            spannableBytes.append(" ")
            currentIdx = end + 1
        }
        
        if (spannableBytes.isNotEmpty()) {
            spannableBytes.delete(spannableBytes.length - 1, spannableBytes.length)
        }
        
        holder.tvBytes.text = spannableBytes
        holder.tvBytes.movementMethod = LinkMovementMethod.getInstance()

        // Alternating row background for Hex view
        holder.itemView.setBackgroundColor(
            android.graphics.Color.parseColor(if (position % 2 == 0) "#090A0F" else "#121420")
        )
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
        
        // Alternating row backgrounds for decompilation view
        holder.itemView.setBackgroundColor(
            android.graphics.Color.parseColor(if (position % 2 == 0) "#090A0F" else "#121420")
        )

        // Apply micro-highlights for optimized, high-fidelity visual scanning
        val trimmed = item.trim()
        when {
            trimmed.startsWith("void ") || trimmed.startsWith("if ") || trimmed.startsWith("return;") || trimmed.startsWith("goto ") -> {
                holder.tvLineText.setTextColor(android.graphics.Color.parseColor("#00E5FF")) // Premium Cyan
            }
            trimmed.startsWith("x") || trimmed.startsWith("w") || trimmed.startsWith("*") -> {
                holder.tvLineText.setTextColor(android.graphics.Color.parseColor("#94A3B8")) // Muted Slate
            }
            trimmed.startsWith("[") -> {
                holder.tvLineText.setTextColor(android.graphics.Color.parseColor("#00FF66")) // Tech Green
            }
            else -> {
                holder.tvLineText.setTextColor(android.graphics.Color.parseColor("#F1F5F9")) // Clean Off-White
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
    private val onItemLongClick: ((View, DisassemblyLine) -> Boolean)? = null
) : ListAdapter<DisassemblyLine, DisassemblyTabAdapter.ViewHolder>(DiffCallback) {

    var resolveDataXrefText: ((Long) -> String?)? = null
    var getJumpTableInfo: ((Long) -> JumpTableInfo?)? = null
    var onBookmarkToggle: ((DisassemblyLine) -> Unit)? = null

    private var highlightAddress: Long? = null

    private val handler = android.os.Handler(android.os.Looper.getMainLooper())
    private var clearHighlightRunnable: Runnable? = null

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
        
        clearHighlightRunnable?.let { handler.removeCallbacks(it) }
        
        if (address != null) {
            val runnable = Runnable {
                val lastHighlight = highlightAddress
                highlightAddress = null
                for (i in 0 until itemCount) {
                    val item = getItem(i)
                    if (item.address == lastHighlight) {
                        notifyItemChanged(i)
                    }
                }
            }
            clearHighlightRunnable = runnable
            handler.postDelayed(runnable, 1500)
        }
    }

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvLineText: TextView = view.findViewById(R.id.tv_line_text)
        val tvCommentText: TextView = view.findViewById(R.id.tv_comment_text)
        val ivLineBookmark: ImageView = view.findViewById(R.id.iv_line_bookmark)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_hex_disassembly_line, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)
        
        if (item.address == -1L) {
            holder.ivLineBookmark.visibility = View.GONE
            holder.tvCommentText.visibility = View.GONE
            val spannable = SpannableStringBuilder("${item.mnemonic}\n${item.opStr}")
            spannable.setSpan(
                ForegroundColorSpan(android.graphics.Color.parseColor("#00FF66")),
                0,
                spannable.length,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            )
            holder.tvLineText.text = spannable
            holder.itemView.setOnClickListener(null)
            holder.itemView.setOnLongClickListener(null)
            return
        } else {
            holder.ivLineBookmark.visibility = View.VISIBLE
        }
        
        val isBookmarked = BookmarkRepository.isBookmarked(item.address)
        if (isBookmarked) {
            holder.ivLineBookmark.setImageResource(android.R.drawable.btn_star_big_on)
        } else {
            holder.ivLineBookmark.setImageResource(android.R.drawable.btn_star_big_off)
        }
        holder.ivLineBookmark.setOnClickListener {
            onBookmarkToggle?.invoke(item)
        }

        val resolvedLabel = AnnotationRepository.resolveAddressName(item.address)
        val addrStr = "0x" + item.address.toString(16).uppercase().padStart(8, '0')
        
        val addrPart = if (resolvedLabel != "sub_${item.address.toString(16).uppercase()}") {
            "$addrStr <$resolvedLabel>:"
        } else {
            "$addrStr:"
        }
        
        val addrPadded = addrPart.padEnd(28)
        val bytesPadded = item.bytesHex.padEnd(16)
        val mnemonicPadded = item.mnemonic.padEnd(8)
        val opPart = item.opStr
        
        val fullLineText = "$addrPadded  $bytesPadded  $mnemonicPadded $opPart"
        
        val builder = SpannableStringBuilder(fullLineText)
        
        // 1. Color Address & Label: Muted Slate Gray (#64748B)
        builder.setSpan(
            ForegroundColorSpan(android.graphics.Color.parseColor("#64748B")),
            0,
            28,
            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
        )
        
        // If there's a label in <...>, color the label with a distinct color, like #00E5FF (sleek cyan)
        val labelStart = addrPart.indexOf('<')
        val labelEnd = addrPart.indexOf('>')
        if (labelStart != -1 && labelEnd != -1 && labelEnd > labelStart) {
            builder.setSpan(
                ForegroundColorSpan(android.graphics.Color.parseColor("#00E5FF")), // Label accent
                labelStart,
                labelEnd + 1,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            )
        }
        
        // 2. Color Bytes: Muted Blue-Gray (#4A5568)
        builder.setSpan(
            ForegroundColorSpan(android.graphics.Color.parseColor("#4A5568")),
            30,
            46,
            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
        )
        
        // 3. Color Mnemonic: Based on instruction type (subtle and consistent)
        val mnemonicStart = 48
        val mnemonicEnd = 56
        val mnemonicColorHex = when (item.mnemonic.lowercase()) {
            "cmp", "tst" -> "#FF007F" // Alert Pink
            "b", "bl", "beq", "bne", "b.eq", "b.ne", "b.ge", "b.lt", "b.gt", "b.le", "jmp", "je", "jne" -> "#00E5FF" // Branch Cyan
            "ldr", "str", "mov" -> "#00FF66" // Load/Store/Move Green
            "add", "sub", "mul", "div" -> "#FFB300" // Arithmetic Gold
            "ret" -> "#FF4F58" // Return Red
            else -> "#F1F5F9" // General White
        }
        builder.setSpan(
            ForegroundColorSpan(android.graphics.Color.parseColor(mnemonicColorHex)),
            mnemonicStart,
            mnemonicStart + item.mnemonic.length,
            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
        )
        builder.setSpan(
            StyleSpan(Typeface.BOLD),
            mnemonicStart,
            mnemonicStart + item.mnemonic.length,
            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
        )
        
        // 4. Color Operands: Clean White (#F1F5F9)
        builder.setSpan(
            ForegroundColorSpan(android.graphics.Color.parseColor("#F1F5F9")),
            57,
            fullLineText.length,
            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
        )
        
        holder.tvLineText.text = builder

        // Handle inline comments
        val jtable = getJumpTableInfo?.invoke(item.address)
        val annotation = AnnotationRepository.getAnnotation(item.address)
        if (jtable != null) {
            holder.tvCommentText.text = "; → switch (${jtable.entryCount} cases)"
            holder.tvCommentText.visibility = View.VISIBLE
            holder.tvCommentText.setTypeface(null, Typeface.BOLD)
            holder.tvCommentText.setTextColor(android.graphics.Color.parseColor("#00E5FF")) // Sleek Cyan
        } else if (annotation != null && !annotation.comment.isNullOrBlank()) {
            holder.tvCommentText.text = "; ${annotation.comment}"
            holder.tvCommentText.visibility = View.VISIBLE
            holder.tvCommentText.setTypeface(null, Typeface.ITALIC)
            holder.tvCommentText.setTextColor(android.graphics.Color.parseColor("#64748B"))
        } else {
            val dataXrefText = resolveDataXrefText?.invoke(item.address)
            if (dataXrefText != null) {
                holder.tvCommentText.text = "; $dataXrefText"
                holder.tvCommentText.visibility = View.VISIBLE
                holder.tvCommentText.setTypeface(null, Typeface.BOLD_ITALIC)
                holder.tvCommentText.setTextColor(android.graphics.Color.parseColor("#FF007F")) // neon magenta/pink
            } else {
                val targetAddr = XrefAnalyzer.extractTargetAddress(item.opStr)
                val resolvedTarget = if (targetAddr != null) AnnotationRepository.resolveAddressName(targetAddr) else null
                if (targetAddr != null && resolvedTarget != null && resolvedTarget != "sub_${targetAddr.toString(16).uppercase()}") {
                    holder.tvCommentText.text = "; $resolvedTarget"
                    holder.tvCommentText.visibility = View.VISIBLE
                    holder.tvCommentText.setTypeface(null, Typeface.ITALIC)
                    holder.tvCommentText.setTextColor(android.graphics.Color.parseColor("#64748B"))
                } else {
                    holder.tvCommentText.visibility = View.GONE
                }
            }
        }

        holder.itemView.setOnClickListener {
            onItemClick?.invoke(item)
        }
        holder.itemView.setOnLongClickListener {
            onItemLongClick?.invoke(holder.itemView, item) ?: false
        }

        if (item.address == highlightAddress) {
            holder.itemView.setBackgroundColor(android.graphics.Color.parseColor("#2600E5FF")) // 15% alpha cyan highlight
        } else {
            // Alternating backgrounds
            holder.itemView.setBackgroundColor(
                android.graphics.Color.parseColor(if (position % 2 == 0) "#090A0F" else "#121420")
            )
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

fun RecyclerView.scrollToAddress(
    matcher: (Int) -> Boolean,
    onFound: (Int) -> Unit
) {
    val adapter = this.adapter ?: return
    val count = adapter.itemCount
    for (i in 0 until count) {
        if (matcher(i)) {
            val layoutManager = this.layoutManager as? androidx.recyclerview.widget.LinearLayoutManager
            layoutManager?.scrollToPositionWithOffset(i, 0)
            onFound(i)
            return
        }
    }
}

// --- RECENT FILES ADAPTER ---

class RecentFilesAdapter(
    private val onItemClick: (RecentFile) -> Unit,
    private val onRemoveClick: (RecentFile) -> Unit
) : ListAdapter<RecentFile, RecentFilesAdapter.ViewHolder>(DiffCallback) {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvName: TextView = view.findViewById(R.id.tv_recent_name)
        val tvMeta: TextView = view.findViewById(R.id.tv_recent_meta)
        val ivRemove: ImageView = view.findViewById(R.id.iv_recent_remove)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_recent_file, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)
        holder.tvName.text = item.displayName
        
        val sizeKb = item.fileSize / 1024
        val sizeStr = if (sizeKb > 1024) {
            String.format("%.1f MB", sizeKb / 1024.0)
        } else {
            "$sizeKb KB"
        }
        
        val timeDiff = System.currentTimeMillis() - item.lastOpened
        val timeStr = when {
            timeDiff < 60000 -> "Just now"
            timeDiff < 3600000 -> "${timeDiff / 60000} mins ago"
            timeDiff < 86400000 -> "${timeDiff / 3600000} hours ago"
            else -> java.text.DateFormat.getDateInstance(java.text.DateFormat.SHORT).format(java.util.Date(item.lastOpened))
        }
        
        holder.tvMeta.text = "$sizeStr | ${item.architecture} | $timeStr"
        
        holder.itemView.setOnClickListener { onItemClick(item) }
        holder.ivRemove.setOnClickListener { onRemoveClick(item) }
    }

    companion object DiffCallback : DiffUtil.ItemCallback<RecentFile>() {
        override fun areItemsTheSame(oldItem: RecentFile, newItem: RecentFile): Boolean {
            return oldItem.uri == newItem.uri
        }
        override fun areContentsTheSame(oldItem: RecentFile, newItem: RecentFile): Boolean {
            return oldItem == newItem
        }
    }
}




