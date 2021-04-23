all:
	dotnet publish src/ipk-sniffer.csproj -r linux-x64 -c Release -o .
clean:	
	rm src/obj -r
	rm src/bin -r
	