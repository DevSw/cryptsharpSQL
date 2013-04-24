CryptSharpSQL
=============

------------------

This fork of ChrisMcKee/crypsharp is to create a SQL CLR compatible assembly.

It has been stripped down, and only the Blowfishcipher.Bcrypt is in use.  It has been tested with SQL Server 2008.

To create assembly in SQL Server run the following, replacing %PATH% with your path to CryptSharpSQL.dll:

<pre><code>
CREATE ASSEMBLY CryptSharpSQL from '%PATH%\CryptSharpSQL.dll' WITH PERMISSION_SET = SAFE
GO
</code></pre>

To add the Crypt Function to SQL:
<pre><code>
CREATE FUNCTION Crypt 
	(
	@password varbinary(70),
	@salt nvarchar(40)
	)
	RETURNS nvarchar(100)
AS
EXTERNAL NAME CryptSharpSQL.[CryptSharpSQL.CrypterSQL].Crypt
GO
</code></pre>

To add the GenerateSalt Function to SQL:
<pre><code>
CREATE FUNCTION GenerateSalt 
	(
	@rounds int
	)
	RETURNS nvarchar(40)
AS
EXTERNAL NAME CryptSharpSQL.[CryptSharpSQL.CrypterSQL].GenerateSalt
GO
</code></pre>

To use in SQL:
<pre><code>
/* Create Salt */
DECLARE @salt nvarchar(40)
SET @salt = dbo.GenerateSalt(6)

/* Create Hash */
DECLARE @hash nvarchar(60)
SET @hash = dbo.Crypt(123456, @salt)

/* test */
Select @hash
Select test = dbo.Crypt(123456, @salt)
</code></pre>


Be aware when using BCrypt that only the first 72 bytes of a password are used. This limitation is not specific to this implementation. If you are likely to pass byte arrays over 72 bytes in length, call PadKeyThenCrypt to have the extra bytes removed.

------------------
_CryptSharp uses the ISC license._