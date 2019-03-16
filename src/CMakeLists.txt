set(LIB_FILES shm_mem.c)

# build the shared library
add_library(${LIB_SHARED} SHARED ${LIB_FILES})

# build the static library
add_library(${LIB_STATIC} STATIC ${LIB_FILES})

# set the static basename to shared basename 
set_target_properties(${LIB_STATIC} PROPERTIES OUTPUT_NAME ${LIB_SHARED})

#install shared lib
INSTALL(TARGETS ${LIB_SHARED} 
        LIBRARY DESTINATION ${OUT_LIB_DIR}
) 

#install static lib
INSTALL(TARGETS ${LIB_STATIC} 
        ARCHIVE DESTINATION ${OUT_LIB_DIR}
)

# install include directory
install(DIRECTORY ${PROJECT_SOURCE_DIR}/${SRC_INC_DIR}/ DESTINATION ${OUT_INC_DIR}
        FILES_MATCHING PATTERN "*.h"
)


