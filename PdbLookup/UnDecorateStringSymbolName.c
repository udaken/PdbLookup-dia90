#include <string.h>
#include <stdint.h>

#ifdef _MSC_VER
#define restrict __restrict 
#endif

#define BETWEEN_A_P(_c) ('A' <= (_c) && (_c) <= 'P')

extern uint32_t UnDecorateStringSymbolName(
	const char* restrict name,
	unsigned char* restrict outputString,
	uint32_t maxStringLength,
	_Bool* restrict pisDoubleBytes);

static char MyToupper(char c)
{
	return ('a' <= c && c <= 'z') ? c + ('a' - 'A') : c;
}

uint32_t UnDecorateStringSymbolName(
	const char* restrict name,
	unsigned char* restrict outputString,
	uint32_t maxStringLength,
	_Bool* restrict pisDoubleBytes)
{
	if (pisDoubleBytes == NULL)
		return 0;

	_Bool isSingleByte = strncmp(name, "??_C@_0", 7) == 0;
	_Bool isDoubleByte = strncmp(name, "??_C@_1", 7) == 0;
	uint32_t outPos = 0;
	if (isSingleByte || isDoubleByte)
	{
		const char* curPos = name + strlen("??_C@_1");
		if (!('0' <= curPos[0] && curPos[0] <= '9')) // not digit char
		{
			const char* atmarkFound = strchr(curPos, '@'); // skip encoded number.
			if (atmarkFound)
			{
				curPos = atmarkFound + 1;
			}
		}

		const char* atmarkFound = strchr(curPos, '@'); // skip hash.
		if (atmarkFound)
		{
			curPos = atmarkFound + 1;
			size_t remains = strlen(curPos);

			while (remains)
			{
				unsigned char c = (unsigned char)(curPos[0]);
				++curPos;
				--remains;
				if (c == '?')
				{
					if (remains > 2 && curPos[0] == '$' && BETWEEN_A_P(curPos[1]) && BETWEEN_A_P(curPos[2]))
					{
						unsigned char hibit = (unsigned char)(curPos[1]) - 'A';
						unsigned char lobit = (unsigned char)(curPos[2]) - 'A';
						c = (unsigned char)(hibit << 4 | lobit);
						curPos += 3;
						remains -= 3;
					}
					else if (remains > 0 && ('0' <= curPos[0] && curPos[0] <= '9'))
					{
						static const unsigned char x[] = { ',','/','\\',':','.',' ',0x11,0x10,'\'','-' };
						c = x[curPos[0] - '0'];
						++curPos;
						--remains;
					}
					else if (remains > 0 && BETWEEN_A_P(MyToupper(curPos[0]))) // 0x41-0x50 or 0x61-0x70
					{
						c = (unsigned char)(curPos[0]) + 0x80;
						++curPos;
						--remains;
					}
				}
				else if (c == '@')
				{
					break;
				}

				if (0 == maxStringLength)
					outPos++;
				else if (outPos < maxStringLength)
					outputString[outPos++] = c;
				else
					return 0; // overflow
			}
			*pisDoubleBytes = isDoubleByte;
			return outPos;
		}
	}
	*pisDoubleBytes = 0;
	if (maxStringLength)
		strncpy_s(outputString, maxStringLength, name, maxStringLength - 1);
	return (uint32_t)((unsigned char*)(memchr(outputString, 0x00, maxStringLength)) - outputString);
}
