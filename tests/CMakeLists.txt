set(TEST_LIST ltest.c rtest.c htest.c)

# library name
set(LIB ${CMAKE_PROJECT_NAME})

# select the library
if (${USE_STATIC})
  set(LIB ${LIB_STATIC})
else()
  set(LIB ${LIB_SHARED})
endif()

message("using lib ${LIB} for tests")

# build the tests
foreach (TEST ${TEST_LIST})

  # strip extension
  get_filename_component(EXE ${TEST} NAME_WE)
  
  # build the code
  message("processing test: ${TEST}, exe: ${EXE}")
  add_executable(${EXE} ${TEST})
    
  # link the lirary
  target_link_libraries(${EXE} ${LIB} -lrt -lpthread)
  
  # install the target
  install(TARGETS ${EXE} 
  	RUNTIME DESTINATION ${BIN_DIR}
  )
  
endforeach(TEST)

