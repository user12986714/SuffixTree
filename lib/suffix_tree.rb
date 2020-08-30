require "suffix_tree/suffix_tree"

class SuffixTree
  VERSION = "0.2.1"
  def self.create!(str_path, tag_path, child_path, node_path)
    __suffix_tree_create! str_path, tag_path, child_path, node_path
  end
end
