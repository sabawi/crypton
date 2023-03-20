    @page { size: 8.5in 11in; margin: 0.79in } p { line-height: 115%; margin-bottom: 0.1in; background: transparent } pre { background: transparent } pre.western { font-family: "Liberation Mono", monospace; font-size: 10pt } pre.cjk { font-family: "Noto Sans Mono CJK SC", monospace; font-size: 10pt } pre.ctl { font-family: "Liberation Mono", monospace; font-size: 10pt } a:link { color: #000080; text-decoration: underline } a:visited { color: #800000; text-decoration: underline }

**Strong 256 CBC Encryption tool for Linux systems**

  

‘**crypton**’ is simple to use. From a Linux terminal command line enter the command directly. You can also wrap it within another program or embed it into your code.
Here is the command line usage:
 
$ **crypton**
Usage : 
	-enc|-dec <filename> : Encrypt or Decrypt file
	-v : Show program version 

Invoking this command with the ‘-enc’ option on a <filename> will create a new file with the extension .encrypted: <filename>.encrypted. 

$ **echo "This is my secret message" >> mysecretfile.txt**
$ **crypton** **-enc mysecretfile.txt**
Password:
Password must be 8 to 25 characters long
Password:
Confirm Password:
Confirmation of passwords failed. Retry! or ctrl-c to exit
Password:
Confirm Password:
File size = 27
Encrypting file ....File encrypted into **'mysecretfile.txt.encrypted'**
Done!
$ **ls mysecretfile.\***
mysecretfile.txt  **mysecretfile.txt.encrypted**

**Make sure you memorize the Password which can be a multi-word phrase of up to 28 characters but no less than 8 characters. You cannot recover the original file without the password!**

To decrypt the file back, invoke the same command above with the ‘-dec’ option followed by the encrypted file <filename>.encrypted.  To reverse the above example:

**$** **crypton** **-dec mysecretfile.txt.encrypted**
Password:
Decrypting file 'mysecretfile.txt.encrypted' ....
27 bytes writen to file 'mysecretfile.txt.decrypted'
Done!

The above will decrypt ‘mysecrestfile.txt.encrypted’ file back to its original format. 

**NOTE:** **DECRYPTING AN ENCRYPTED FILE WILL NOT OVERWRITE THE ORIGINAL FILE**. 

The decrypted file will be called **<filename>.decrypted**.  In the above example the decrypted file will be generated with the name **'mysecretfile.txt.decrypted'**

Enjoy!

Al
