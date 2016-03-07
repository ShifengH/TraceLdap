int Trace(char *Buff_PDU)
{
	int r = 0;
	
}

char *reset()
  {
   return origOffset;
  }
  
int getParsePosition()
  {
    return this.offset;
  }
  
   int parseLength(char *offset)
  {
    int i = parseByte(char *offset);
    
    if ((i & 0x80) == 128)
    {
      i &= 127;
      
      if (i == 0) {
	printf("Error decoding Length supposed to be not 0 @FILE:%s,line:%d\n", __FILE__,__LINE__);
	return -1;
      }
      
      if (i > 4) {
	printf("Not support too long @FILE:%s,line:%d\n", __FILE__,__LINE__);
	return -1;
      }
      
      
      int j = 0;
      //i now = 1,2,3,4. no more.
      for (int k = 0; k < i; k++) {
        j = (j << 8) + ((&offset++) & 0xFF);
      }
      return j;
    }
    return i;
  }
  
   int parseSeq(int[] paramArrayOfInt)
    throws Ber.DecodeException
  {
    int i = parseByte();
    int j = parseLength();
    if (paramArrayOfInt != null) {
      paramArrayOfInt[0] = j;
    }
    return i;
  }
  
  void seek(int paramInt)
    throws Ber.DecodeException
  {
    if ((this.offset + paramInt > this.bufsize) || (this.offset + paramInt < 0)) {
      throw new Ber.DecodeException("array index out of bounds");
    }
    this.offset += paramInt;
  }
  
   char parseByte(char *offset)
  {
    return &offset;
  }
  
   int peekByte()
    throws Ber.DecodeException
  {
    if (this.bufsize - this.offset < 1) {
      throw new Ber.DecodeException("Insufficient data");
    }
    return this.buf[this.offset] & 0xFF;
  }
  
   boolean parseBoolean()
    throws Ber.DecodeException
  {
    return parseIntWithTag(1) != 0;
  }
  
   int parseEnumeration()
    throws Ber.DecodeException
  {
    return parseIntWithTag(10);
  }
  
   int parseInt()
    throws Ber.DecodeException
  {
    return parseIntWithTag(2);
  }
  
  private int parseIntWithTag(int paramInt)
    throws Ber.DecodeException
  {
    if (parseByte() != paramInt) {
      throw new Ber.DecodeException("Encountered ASN.1 tag " + 
        Integer.toString(this.buf[(this.offset - 1)] & 0xFF) + 
        " (expected tag " + Integer.toString(paramInt) + ")");
    }
    
    int i = parseLength();
    
    if (i > 4)
      throw new Ber.DecodeException("INTEGER too long");
    if (i > this.bufsize - this.offset) {
      throw new Ber.DecodeException("Insufficient data");
    }
    
    int j = this.buf[(this.offset++)];
    int k = 0;
    
    k = j & 0x7F;
    for (int m = 1; m < i; m++) {
      k <<= 8;
      k |= this.buf[(this.offset++)] & 0xFF;
    }
    
    if ((j & 0x80) == 128) {
      k = -k;
    }
    
    return k;
  }
  
   String parseString(boolean paramBoolean)
    throws Ber.DecodeException
  {
    return parseStringWithTag(4, paramBoolean, null);
  }
  
   String parseStringWithTag(int paramInt, boolean paramBoolean, int[] paramArrayOfInt)
    throws Ber.DecodeException
  {
    int j = this.offset;
    int i;
    if ((i = parseByte()) != paramInt) {
      throw new Ber.DecodeException("Encountered ASN.1 tag " + 
        Integer.toString((byte)i) + " (expected tag " + paramInt + ")");
    }
    
    int k = parseLength();
    
    if (k > this.bufsize - this.offset) {
      throw new Ber.DecodeException("Insufficient data");
    }
    
    String str;
    if (k == 0) {
      str = "";
    } else {
      byte[] arrayOfByte = new byte[k];
      
      System.arraycopy(this.buf, this.offset, arrayOfByte, 0, k);
      if (paramBoolean) {
        try {
          str = new String(arrayOfByte, "UTF8");
        } catch (UnsupportedEncodingException localUnsupportedEncodingException1) {
          throw new Ber.DecodeException("UTF8 not available on platform");
        }
      } else {
        try {
          str = new String(arrayOfByte, "8859_1");
        } catch (UnsupportedEncodingException localUnsupportedEncodingException2) {
          throw new Ber.DecodeException("8859_1 not available on platform");
        }
      }
      this.offset += k;
    }
    
    if (paramArrayOfInt != null) {
      paramArrayOfInt[0] = (this.offset - j);
    }
    
    return str;
  }
  
   byte[] parseOctetString(int paramInt, int[] paramArrayOfInt)
    throws Ber.DecodeException
  {
    int i = this.offset;
    int j;
    if ((j = parseByte()) != paramInt)
    {
      throw new Ber.DecodeException("Encountered ASN.1 tag " + 
        Integer.toString(j) + 
        " (expected tag " + Integer.toString(paramInt) + ")");
    }
    
    int k = parseLength();
    
    if (k > this.bufsize - this.offset) {
      throw new Ber.DecodeException("Insufficient data");
    }
    
    byte[] arrayOfByte = new byte[k];
    if (k > 0) {
      System.arraycopy(this.buf, this.offset, arrayOfByte, 0, k);
      this.offset += k;
    }
    
    if (paramArrayOfInt != null) {
      paramArrayOfInt[0] = (this.offset - i);
    }
    
    return arrayOfByte;
  }
  
   int bytesLeft()
  {
    return this.bufsize - this.offset;
  }
}

