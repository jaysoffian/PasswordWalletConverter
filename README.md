Convert PasswordWallet export files to 1Password 1pif format.

    Usage: PasswordWalletConverter.py <txt_export> <html_export>

To use, you must export your PasswordWallet twice:

<pre>
1. File > Export > Visible entries to text file...

   Save the file to your Desktop.

2. File > Export > to Stand-alone encrypted web pages...

   Split up into multiple pages with...  Don't split up
   Split up each page into groups with... Don't split up
   Display font: helvetica, arial, sans-serif
   Display font size: Small(+0)
   [ ] Export pages as raw bookmarklets
   [ ] Automatically export when this file is closed

   Then click Export and save the file to your Desktop.

</pre>

Feed both files into this program:

    ./PasswordWalletConverter.py ~/Desktop/PasswordWallet*

This will create `data.1pif` in the current directory, which may
be imported by 1Password.

When done, securely erase both PasswordWallet exports and `data.1pif`
by placing in the Trash and using Finder > Secure Empty Trash.

You may wish to disable any backup programs from running until you're
done so that the unencrypted files don't get backed up.
