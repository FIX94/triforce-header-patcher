/* 
 * Triforce Header Patcher
 * Copyright (C) 2015 FIX94
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "sha1.h"
#include "staticVals.h"

void printerr(char *msg)
{
	puts(msg);
	puts("Press enter to exit");
	getc(stdin);
}

void handleIso(FILE *f, const unsigned char *wantHdr)
{
	if(!f)
	{
		printerr("Something went wrong with the file!");
		exit(-1);
	}
	fseek(f,0,SEEK_SET);

	unsigned char gameHdr[0x40];
	fread(gameHdr,0x40,1,f);
	if(memcmp(gameHdr,wantHdr,0x40) == 0)
		puts("Header already patched!");
	else
	{
		fseek(f,0,SEEK_SET);
		fwrite(wantHdr,0x40,1,f);
		puts("New Header written in!");
	}
}

int gpOverdump(FILE *f, size_t fsize)
{
	unsigned char fbuf[0x100];
	unsigned char cmpBuf[8] = { 0xB9, 0x91, 0xFB, 0xC2, 0xD5, 0xB9, 0x02, 0x44 };

	fseek(f, 0x15000000, SEEK_SET);
	if(fsize == 0x15000010)
	{
		fread(fbuf,1,0x10,f);
		if((memcmp(fbuf,cmpBuf,8) != 0) || (memcmp(fbuf+8,cmpBuf,8) != 0))
			return 0;
	}
	else if(fsize == 0x18000000)
	{
		while(ftell(f) < 0x18000000)
		{
			fread(fbuf,1,0x100,f);
			size_t i;
			for(i = 0; i < 0x100; i+=8)
			{
				if(memcmp(fbuf+i,cmpBuf,8) != 0)
					return 0;
			}
		}
	}
	else //huh
		return 0;
	return 1;
}

void getBodySha1(FILE *f, size_t fsize, void *chksum)
{
	puts("Calculating SHA1...");
	size_t i;
	SHA1_CONTEXT fSha1;
	sha1_init(&fSha1);

	unsigned char *fbuf = malloc(0x1000000);
	fseek(f, 0x40, SEEK_SET); //doing body only
	for(i = 0x40; i < fsize; i += 0x1000000)
	{
		size_t readsize = (fsize - i) < 0x1000000 ? (fsize - i) : 0x1000000;
		fread(fbuf, 1, readsize, f);
		sha1_write(&fSha1, fbuf, readsize);
	}
	free(fbuf);

	sha1_final(&fSha1);
	memcpy(chksum, fSha1.buf, 20);

	//for(i = 0; i < 19; i++)
	//	printf("0x%02x, ", fSha1.buf[i]);
	//printf("0x%02x\n", fSha1.buf[i]);
}

void fixVs4v06Jap(FILE *f)
{
	fseek(f,0x1D413000,SEEK_SET);
	unsigned char fbuf[0x14];
	fread(fbuf,1,0x14,f);
	if(memcmp(fbuf,bad_tex_sw_yuk,0x14) == 0)
	{
		fseek(f,0x1D413000,SEEK_SET);
		fwrite(good_tex_sw_yuk,1,0x14,f);
		puts("Fixed a known dump error!");
	}
}

int isSha1of(const void *chksum1, const void *chksum2, const char *name)
{
	if(memcmp(chksum1,chksum2,20) == 0)
	{
		printf("Valid %s SHA1!\n", name);
		return 1;
	}
	return 0;
}

void printUnkChksum(unsigned char *chksum)
{
	printf("Unknown SHA1: ");
	size_t i;
	for(i = 0; i < 19; i++)
		printf("%02x", chksum[i]);
	printf("%02x\n", chksum[i]);
}

int main(int argc, char *argv[])
{
	puts("Triforce Header Patcher v1.1 by FIX94");
	if(argc != 2)
	{
		printerr("Please drag and drop a file into this exe.");
		return -1;
	}
	FILE *f = fopen(argv[1],"rb+");
	if(!f)
	{
		printerr("File could not be opened/edited! Make sure it exists and you have rights to edit it.");
		return -2;
	}
	fseek(f,0,SEEK_END);
	size_t fsize = ftell(f);
	unsigned char chksum[20];
	if(fsize == 0x19FCC500)
	{
		puts("Guessing F-Zero AX");
		getBodySha1(f, 0x19FCC500, chksum);
		if(isSha1of(chksum, ax_unk_chksum, "F-Zero AX [Unknown]") || isSha1of(chksum, ax_4c_chksum, "F-Zero AX [GDT-0004C]")
		 || isSha1of(chksum, ax_4e_chksum, "F-Zero AX [GDT-0004E]"))
			handleIso(f, axHdr);
		else
			printUnkChksum(chksum);
	}
	else if(fsize == 0x15000000)
	{
		puts("Guessing Mario Kart Arcade GP");
		getBodySha1(f, 0x15000000, chksum);
		if(isSha1of(chksum, gp_unk_chksum, "Mario Kart Arcade GP [Unknown]"))
			handleIso(f, gpHdr);
		else
			printUnkChksum(chksum);
	}
	else if(fsize == 0x15000010 && gpOverdump(f,fsize))
	{
		puts("Guessing Mario Kart Arcade GP (Overdump 1)");
		getBodySha1(f, 0x15000000, chksum);
		if(isSha1of(chksum, gp_unk_chksum, "Mario Kart Arcade GP [Unknown]"))
		{
			_chsize(fileno(f), 0x15000000); //windows only bleh
			puts("Adjusted filesize!");
			handleIso(f, gpHdr);
		}
		else
			printUnkChksum(chksum);
	}
	else if(fsize == 0x18000000 && gpOverdump(f,fsize))
	{
		puts("Guessing Mario Kart Arcade GP (Overdump 2)");
		getBodySha1(f, 0x15000000, chksum);
		if(isSha1of(chksum, gp_unk_chksum, "Mario Kart Arcade GP [Unknown]"))
		{
			_chsize(fileno(f), 0x15000000); //windows only bleh
			puts("Adjusted filesize!");
			handleIso(f, gpHdr);
		}
		else
			printUnkChksum(chksum);
	}
	else if(fsize == 0x1E000000)
	{
		puts("Guessing Mario Kart Arcade GP 2");
		getBodySha1(f, 0x1E000000, chksum);
		if(isSha1of(chksum, gp2_unk_chksum, "Mario Kart Arcade GP 2 [Unknown]"))
			handleIso(f, gp2Hdr);
		else
			printUnkChksum(chksum);
	}
	else if(fsize == 0x1EF00000)
	{
		puts("Guessing Gekitou Pro Yakyuu");
		getBodySha1(f, 0x1EF00000, chksum);
		if(isSha1of(chksum, gpb_8b_chksum, "Gekitou Pro Yakyuu [GDT-0008B]") || isSha1of(chksum, gpb_8c_chksum, "Gekitou Pro Yakyuu [GDT-0008C]"))
			handleIso(f, gpbHdr);
		else
			printUnkChksum(chksum);
	}
	else if(fsize == 0x1262C0A8)
	{
		puts("Guessing Virtua Striker 3 Ver. 2002");
		getBodySha1(f, 0x1262C0A8, chksum);
		if(isSha1of(chksum, vs3v02jap_1_chksum, "Virtua Striker 3 Ver. 2002 (Japan) [GDT-0001]"))
			handleIso(f, vs3v02japHdr);
		else if(isSha1of(chksum, vs3v02exp_2_chksum, "Virtua Striker 3 Ver. 2002 (Export) [GDT-0002]"))
			handleIso(f, vs3v02expHdr);
		else
			printUnkChksum(chksum);
	}
	else if(fsize == 0x1CA1A400)
	{
		puts("Guessing Virtua Striker 4");
		getBodySha1(f, 0x1CA1A400, chksum);
		if(isSha1of(chksum, vs4jap_13e_chksum, "Virtua Striker 4 (Japan) [GDT-0013E]"))
			handleIso(f, vs4japHdr);
		else if(isSha1of(chksum, vs4exp_15_chksum, "Virtua Striker 4 (Export) [GDT-0015]"))
			handleIso(f, vs4expHdr);
		else
			printUnkChksum(chksum);
	}
	else if(fsize == 0x1CA20000)
	{
		puts("Guessing Virtua Striker 4 (Overdump 1)");
		getBodySha1(f, 0x1CA1A400, chksum);
		if(isSha1of(chksum, vs4jap_13e_chksum, "Virtua Striker 4 (Japan) [GDT-0013E]"))
		{
			_chsize(fileno(f), 0x1CA1A400); //windows only bleh
			puts("Adjusted filesize!");
			handleIso(f, vs4japHdr);
		}
		else if(isSha1of(chksum, vs4exp_15_chksum, "Virtua Striker 4 (Export) [GDT-0015]"))
		{
			_chsize(fileno(f), 0x1CA1A400); //windows only bleh
			puts("Adjusted filesize!");
			handleIso(f, vs4expHdr);
		}
		else
			printUnkChksum(chksum);
	}
	else if(fsize == 0x1D4130C8)
	{
		puts("Guessing Virtua Striker 4 Ver. 2006 (Japan)");
		fixVs4v06Jap(f); // important to do before SHA1
		getBodySha1(f, 0x1D4130C8, chksum);
		if(isSha1of(chksum, vs4v06jap_20d_chksum, "Virtua Striker 4 Ver. 2006 (Japan) [GDT-0020D]"))
			handleIso(f, vs4v06japHdr);
		else
			printUnkChksum(chksum);
	}
	else if(fsize == 0x1CA13288)
	{
		puts("Guessing Virtua Striker 4 Ver. 2006 (Export)");
		getBodySha1(f, 0x1CA13288, chksum);
		if(isSha1of(chksum, vs4v06exp_21_chksum, "Virtua Striker 4 Ver. 2006 (Export) [GDT-0021]"))
			handleIso(f, vs4v06expHdr);
		else
			printUnkChksum(chksum);
	}
	else
		puts("Unknown file, did nothing");
	fclose(f);
	puts("Press enter to exit");
	getc(stdin);
	return 0;
}
