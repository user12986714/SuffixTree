Gem::Specification.new do |s|
  s.name = "suffix_tree"
  s.version = "0.0.0"
  s.date = "2020-08-16"
  s.summary = "A terribly implemented suffix tree gem for Ruby"
  s.authors = %w[user12986714]
  s.homepage = "https://github.com/user12986714/SuffixTree"
  s.files = %w[
    LICENSE
    ext/suffix_tree/suffix_tree.c
    ext/suffix_tree/extconf.rb
    lib/suffix_tree.rb
  ]
  s.license = "Unlicense"
  s.extensions = %w[ext/suffix_tree/extconf.rb]
end
