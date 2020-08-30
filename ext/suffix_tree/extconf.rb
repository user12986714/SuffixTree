require 'mkmf'

append_cflags('-O3')
append_cflags('-Ofast')

create_makefile 'suffix_tree/suffix_tree'
