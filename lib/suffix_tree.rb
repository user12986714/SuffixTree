require "suffix_tree/suffix_tree"

class SuffixTree
  VERSION = "0.0.0"
  def self.create!(path)
    __suffix_tree_create! path
  end
end
