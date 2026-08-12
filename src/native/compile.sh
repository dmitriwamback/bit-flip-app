em++ main.cpp -o main.mjs \
     -s MODULARIZE=1 \
     -s EXPORT_ES6=1 \
     -s EXPORT_NAME=createPatcherModule \
     -s ENVIRONMENT=web \
     -s NO_DISABLE_EXCEPTION_CATCHING \
     --bind -O2