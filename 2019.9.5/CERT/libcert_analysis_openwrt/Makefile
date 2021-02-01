CC := gcc
#CC := arm-himix100-linux-gcc
LIBS := 
LDFLAGS := -L./lib
DEFINES := 
INCLUDE := -I ./include
CFLAGS := 
CXXFLAGS:= 

LIB := libcert.so 


$(LIB):cert.o 
	$(CC) -shared -o -fPIC -o $@ $^ $(INCLUDE) $(LDFLAGS) 
cert.o: cert.c
	$(CC) -c -fPIC $^ -o $@ $(INCLUDE)


clean: 
	rm -fr *.o *.so   test
