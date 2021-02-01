CC := gcc
LIBS := 
LDFLAGS := -L./lib
DEFINES := 
INCLUDE := -I ./include
CFLAGS := 
CXXFLAGS:= 

LIB := libcertformat.so 


$(LIB):certformat.o 
	$(CC) -shared -o -fPIC -o $@ $^ $(INCLUDE) $(LDFLAGS) 
certformat.o: certformat.c
	$(CC) -c -fPIC $^ -o $@ $(INCLUDE)


clean: 
	rm -fr *.o *.so  test