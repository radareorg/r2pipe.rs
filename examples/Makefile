all: main quit

main:
	rustc -L ../target/debug/ -L ../target/debug/deps main.rs 
	r2 -qc '#!pipe ./main' /bin/ls

async:
	rustc -L ../target/debug/ -L ../target/debug/deps async.rs

#	r2 -qc '#!pipe ./async' /bin/ls

quit:
	rustc -L ../target/debug/ -L ../target/debug/deps quit.rs 
	r2 -qc '#!pipe ./quit' /bin/ls

.PHONY: main quit async
