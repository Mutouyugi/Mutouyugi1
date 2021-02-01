CC := gcc
LIBS := 
LDFLAGS := -L./
DEFINES := 
INCLUDE := -I ./
CFLAGS := 
CXXFLAGS:= 

LIB := libcertc.so 


$(LIB):libcertc.o 
	$(CC) -shared -o -fPIC -o $@ $^ $(INCLUDE) $(LDFLAGS) 
libcertc.o: certc.c
	$(CC) -c -fPIC $^ -o $@ $(INCLUDE)


clean: 
	rm -fr *.o *.so   test