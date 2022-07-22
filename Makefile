CXXFLAGS += -g
LDFLAGS += -lstdc++ -lpe -lssl -lcapstone -ltbb

xsplit: xsplit.o symbol_map.o object_list.o pe_file.o threaded_disassembler.o characteristics_lookup_gen.o
