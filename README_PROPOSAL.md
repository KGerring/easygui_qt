# easygui_cryptography: My love-letter to easygui-qt!


One of python's biggest weaknesses is how complicated implementing a GUI (for even simple tasks). Don't get me wrong... 98% of my programming is done in Python, but it made even simple dialogs/pickers very frustrating. UNTIL... I came across [easygui_qt](https://github.com/aroberge/easygui_qt) (and [easygui](https://github.com/robertlugg/easygui) for tkinter). People seemed to either need a very advanced GUI or a simple one for getting quick user-input or displaying a notification. This package is made for the latter-group, and was really simple to understand and use when I first started programming. 

When tooling around on the console I found I would often accidentally display the masked-password I just asked for, so I wrote a script to address that. It __encodes__ your function-returns either to 

  * base64 (for prying looks over the shoulder) or it can 
  * __encrypt__ it in using a symmetrical block cipher, [AES](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard), found in [pycrypto](http://www.pycrypto.org/). 

It calls the desired [easygui_qt](https://github.com/aroberge/easygui_qt) function(*without* modifying the original source code), but does its thing before it hands it back to you. 

I also wrote functions that will generate both the encrypt and decrypt functions together with the option of including the default or user-generated key within the functions, so you don't lose them. 

Finally, the simple **base64 mask/unmask**, **AES encrypt/decrypt**, **utf-8 encode(string)/decode(bytes)** functions themselves are included as an additional text-manipulation resource.
