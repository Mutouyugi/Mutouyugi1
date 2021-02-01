CC := gcc
LIBS := 
LDFLAGS := -L./lib
DEFINES := 
INCLUDE := -I ./include
CFLAGS := 
CXXFLAGS:= 

LIB := libcertCheck.so 


$(LIB):certCheck.o
	$(CC) -shared -o -fPIC -o $@ $^ $(INCLUDE) $(LDFLAGS) 
certCheck.o: certCheck.c	
	$(CC) -c -fPIC $^ -o $@ $(INCLUDE)

clean: 
	rm -fr 	*.o *.so    test   


