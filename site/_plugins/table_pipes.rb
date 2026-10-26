# kramdown keeps "\|" literally inside code spans in table cells; GitHub shows "|".
Jekyll::Hooks.register [:pages, :documents], :post_render do |doc|
  next unless doc.output_ext == ".html"
  doc.output = doc.output.gsub(%r{<td\b[^>]*>.*?</td>}m) { |cell| cell.gsub("\\|", "|") }
end
