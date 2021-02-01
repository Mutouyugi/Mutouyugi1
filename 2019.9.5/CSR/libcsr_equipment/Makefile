CC := gcc
LIBS := 
LDFLAGS := -L./lib
DEFINES := 
INCLUDE := -I ./include
CFLAGS := 
CXXFLAGS:= 

LIB :=libcsr.so


$(LIB):libcsr.o 
	$(CC) -shared -o -fPIC -o $@ $^ $(INCLUDE) $(LDFLAGS) 
libcsr.o: libcsr.c
	$(CC) -c -fPIC $^ -o $@ $(INCLUDE)


clean: 
	rm -fr   *.o   *.so   *.key   *.csr   *.pem 	001   core *.txt
