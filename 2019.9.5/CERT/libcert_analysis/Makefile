CC := gcc
LIBS := 
LDFLAGS := -L./lib
DEFINES := 
INCLUDE := -I ./include
CFLAGS := 
CXXFLAGS:= 

LIB := libcert.so 


$(LIB):libcert.o 
	$(CC) -shared -o -fPIC -o $@ $^ $(INCLUDE) $(LDFLAGS) 
libcert.o: cert.c
	$(CC) -c -fPIC $^ -o $@ $(INCLUDE)


clean: 
	rm -fr *.o *.so   test
