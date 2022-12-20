# Format of the Static Variables Trace File
The `static-vars.out` file contains the information on static variables that is needed for the taint analysis module. 
The following list explains the sections of the static variables trace file.

Whenever Pin instruments a binary (application or shared library), image IDs are assigned to each component. Usually, ID 1 refers to the application itself, ID 2 and 3 refer to vDSO and the dynamic linker (which have to be ignored in Cipherfix), ID 4 to libc, and subsequent IDs to the application's other dependencies.


## Images
- `imageCount`: Number of image files
- `imageCount` times:
  - `imageId`: Image file ID
  - `imageSize`: Total size of the image file (hex)
  - `imageFlag`: Flag whether the image has to be considered (1) in the analysis phase or not (0)
  - `imageName`: Image file name

## Static Variables
- `staticVarsCount`: Number of static variables that are found by the pintool
- `staticVarsCount`times:
  - `imageId`: Image file ID
  - `offset`: Offset of the static variable in image memory (hex)
  - `staticVarSize`: Size of the static variable (dec)