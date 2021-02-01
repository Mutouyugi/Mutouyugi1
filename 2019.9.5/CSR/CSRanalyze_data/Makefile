CC := gcc
LIBS := 
LDFLAGS := -L./lib
DEFINES := 
INCLUDE := -I ./include
CFLAGS := 
CXXFLAGS:= 

LIB := libcsranay.so 


$(LIB):libcsranay.o 
	$(CC) -shared -o -fPIC -o $@ $^ $(INCLUDE) $(LDFLAGS) 
libcsranay.o: csranay.c
	$(CC) -c -fPIC $^ -o $@ $(INCLUDE)


clean: 
	rm -fr *.o *.so   test
