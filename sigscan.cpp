#include <cinttypes>
#include <iomanip>

#include "binaryninjaapi.h"

using namespace BinaryNinja;

#define WILD_BYTE -1 // used to identify wild byte when searching for a signature

// converts string signature to array of bytes
// works only with NORM signature type
std::vector<uint8_t> parse_hex_string(const std::string& input)
{
	std::vector<uint8_t> output;

	std::istringstream iss(input);
	std::string token;
	while (std::getline(iss, token, ' '))
	{
		if (token == "?" || token == "??")
		{
			output.push_back(WILD_BYTE);
		}
		else
		{
			int value = std::stoi(token, nullptr, 16);
			output.push_back(value);
		}
	}

	return output;
}

// converts single instruction to a signature, determines whether each byte should preserved as is or replaced with a wild byte
// enhanced & fixed version of community binja python sigmaker plugin, for more information check readme
void instruction_to_sig(BinaryView* bv, uint64_t addr, size_t inst_length, std::vector<BNConstantReference> consts,
	std::stringstream& sigStream, bool allow_custom_wildcard)
{
	const std::string wildcard =
		allow_custom_wildcard ? Settings::Instance()->Get<std::string>("nativeSigScan.outNormSigWildcard") : "?";

	auto br = BinaryReader(bv);
	br.Seek(addr);

	if (consts.empty())
	{
		while (inst_length--)
		{
			sigStream
				<< std::hex << std::uppercase << std::setw(2) << std::setfill('0')
				<< static_cast<unsigned int>(br.Read8()) << " ";
		}
	}
	else
	{
		int new_delta = 0;
		for (const auto& cur_const : consts)
		{
			if (cur_const.pointer)
			{
				new_delta += 4;
			}
			else
			{
				int32_t four_bytes;
				bv->Read(&four_bytes, addr + inst_length - (new_delta + 4), sizeof(int32_t));
				if (cur_const.value == four_bytes)
				{
					new_delta += 4;
				}
				else
				{
					int8_t one_byte;
					bv->Read(&one_byte, addr + inst_length - (new_delta + 1), sizeof(int8_t));
					if (cur_const.value == one_byte)
					{
						new_delta += 1;
					}
				}
			}
		}

		br.Seek(addr);
		for (size_t x = 0; x < inst_length - new_delta; ++x)
		{
			sigStream
				<< std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (unsigned int)br.Read8() << " ";
		}
		for (int x = 0; x < new_delta; ++x)
		{
			sigStream << wildcard << " ";
		}
	}
}

#ifdef WIN32
std::string get_clipboard_text()
{
	if (!::OpenClipboard(nullptr))
	{
		LogError("Failed to open clipboard");
		return std::string {};
	}

	HANDLE hData = ::GetClipboardData(CF_TEXT);
	if (!hData)
	{
		::CloseClipboard();
		LogError("Failed to get clipboard data");
		return std::string {};
	}

	char* pszText = static_cast<char*>(::GlobalLock(hData));
	if (!pszText)
	{
		::GlobalUnlock(hData);
		::CloseClipboard();
		LogError("Failed to extract clipboard data");
		return std::string {};
	}

	std::string clipboard_data(pszText);

	::GlobalUnlock(hData);

	::CloseClipboard();
	return clipboard_data;
}

bool set_clipboard_text(const std::string& text)
{
	if (!::OpenClipboard(nullptr))
	{
		LogError("Failed to open clipboard");
		return false;
	}

	if (!::EmptyClipboard())
	{
		::CloseClipboard();
		LogError("Failed to empty clipboard");
		return false;
	}

	HGLOBAL hData = ::GlobalAlloc(GMEM_MOVEABLE, (text.length() + 1) * sizeof(char));
	if (!hData)
	{
		::CloseClipboard();
		LogError("Failed to allocate memory for clipboard data");
		return false;
	}

	char* pszText = static_cast<char*>(::GlobalLock(hData));
	if (!pszText)
	{
		::GlobalFree(hData);
		::CloseClipboard();
		LogError("Failed to lock memory for clipboard data");
		return false;
	}

	std::strcpy(pszText, text.c_str());

	::GlobalUnlock(hData);

	if (!::SetClipboardData(CF_TEXT, hData))
	{
		::GlobalFree(hData);
		::CloseClipboard();
		LogError("Failed to set clipboard data");
		return false;
	}

	::CloseClipboard();
	return true;
}
#endif

enum sig_types
{
	NORM,
	CODE
};

void create_sig(BinaryView* view, uint64_t start, uint64_t length, sig_types type)
{
	if (view->GetCurrentView().find("Raw") != std::string::npos || view->GetCurrentView().find("Hex") != std::string::npos)
	{
		Log(ErrorLog, "CANNOT CREATE SIG FROM RAW OR HEX VIEW");
		return;
	}

	std::string pattern;
	std::stringstream sig_stream;
	bool instruction_parsing = view->GetAnalysisFunctionsContainingAddress(start).size() > 0;

	if (instruction_parsing)
	{
		auto func = view->GetAnalysisFunctionsContainingAddress(start)[0];
		while (length > 0)
		{
			const auto consts = func->GetConstantsReferencedByInstruction(func->GetArchitecture(), start);
			const auto inst_length = view->GetInstructionLength(func->GetArchitecture(), start);

			instruction_to_sig(view, start, inst_length, consts, sig_stream, type == NORM);

			start += inst_length;
			length -= inst_length;
		}
	}
	else
	{
		instruction_to_sig(view, start, length, {}, sig_stream, type == NORM);
	}

	pattern = std::string {sig_stream.str().substr(0, sig_stream.str().size() - 1)};

	if (type == CODE)
	{
		// variables
		std::string token, mask;

		// create mask
		while (std::getline(sig_stream, token, ' '))
		{
			mask.push_back(token == "?" ? '?' : 'x');
		}

		// create pattern
		std::size_t pos = 0;
		while ((pos = pattern.find(' ', pos)) != std::string::npos)
		{
			pattern.replace(pos, 1, "\\x");
			pos += 2;
		}
		pos = 0;
		while ((pos = pattern.find('?', pos)) != std::string::npos)
		{
			pattern.replace(pos, 1, "00");
			pos += 2;
		}
		pattern = "\"\\x" + pattern + "\", \"" + mask + "\"";
	}

#ifdef WIN32
	if (!set_clipboard_text(pattern))
	{
		LogError("Failed to copy sig to clipboard");
	}
#endif

	if (!instruction_parsing) { pattern += " [RAW BYTES - NO WILDCARDS]"; }
	Log(instruction_parsing ? InfoLog : WarningLog, "%s", pattern.c_str());
}

void replace_all(std::string& str, const std::string& from, const std::string& to)
{
	if (from.empty()) { return; }
	size_t start_pos = 0;
	while((start_pos = str.find(from, start_pos)) != std::string::npos)
	{
		str.replace(start_pos, from.length(), to);
		start_pos += to.length();
	}
}

std::string exctract_sig(std::string str, sig_types type, bool scan_for_custom_wildcard)
{
	std::string sig;
	if (type == NORM)
	{
		//replace custom wildcards with question marks
		if (scan_for_custom_wildcard)
		{
			std::string custom_wildcard = Settings::Instance()->Get<std::string>("nativeSigScan.outNormSigWildcard");
			replace_all(str, custom_wildcard, "?");
		}

		// should work on stuff like:
		// "48 89 5c 24 08 ? 9a
		// 48 89 5C 24 08 ?? 9A'
		bool have_byte = false;
		int cur_byte_len = 0;
		for (auto& c : str)
		{
			if (have_byte && c == ' ')
			{
				if (cur_byte_len > 2) { return ""; }
				sig += " ";
				have_byte = false;
				cur_byte_len = 0;
			}
			else
			{
				if ((c < 'a' || c > 'f') && (c < 'A' || c > 'F') && (c < '0' || c > '9') && c != '?')
				{
					continue;
				}
				else if (c == '?')
				{
					sig += "?";
					++cur_byte_len;
					have_byte = true;
				}
				else
				{
					if (!sig.empty() && sig.back() != ' ')
					{
						have_byte = true;
					}
					sig += c;
					++cur_byte_len;
				}
			}
		}
	}
	else
	{
		// should work on stuff like:
		// "\x48\x89\x5c\x24\x08\x00\x9a", "xxxxx?x"
		// \x48\x89\x5C\x24\x08\x00\x9A", "xxxxx?x"'

		// PATTERN
		// find first occurrence of "\\x" in str
		size_t pos = str.find("\\x");
		// keep reading two characters after each "\\x"
		while (pos != std::string::npos)
		{
			// check if there are at least two characters after "\\x"
			if (pos + 2 < str.size() - 1 && str[pos] == '\\' && str[pos + 1] == 'x')
			{
				// read the next two characters
				std::string hex_str = str.substr(pos + 2, 2);
				// append to the sig string
				sig += hex_str + " ";
				// move to next possible byte in pattern
				pos += 4;
			}
			else
			{
				break;
			}
		}

		// MASK
		// find the first occurrence of ',' after pos in str
		pos = str.find(',', pos);
		if (pos != std::string::npos)
		{
			// read characters until is 'x' or '?'
			while (pos < str.size() && str[pos] != 'x' && str[pos] != '?')
			{
				++pos;
			}
			// read characters until the end of the string or a character that is not 'x' or '?'
			for (size_t i = pos, j = 0; i < str.size() && j * 3 + 2 < sig.size(); ++i, ++j)
			{
				char c = str[i];
				if (c == '?')
				{
					sig[j * 3] = '?';
					sig[j * 3 + 1] = '?';
				}
				else if (c != 'x')
				{
					break;
				}
			}
		}
	}
	if (sig.back() == ' ') { sig.pop_back(); }
	return sig;
}

void find_sig(BinaryView* view, sig_types type)
{
	std::string input_data /*= get_clipboard_text()*/;
	if (!GetTextLineInput(input_data, "Enter signature to find", "Native SigScan"))
	{
		Log(ErrorLog, "FAILED TO GRAB INPUT");
		return;
	}

	if (input_data.empty())
	{
		Log(ErrorLog, "INPUT DOES NOT CONTAIN ANY TEXT");
		return;
	}
	// Log(InfoLog, "input_data: %s", input_data.c_str());

	const std::string sig = exctract_sig(input_data, type,
		type == NORM && Settings::Instance()->Get<bool>("nativeSigScan.inNormSigScanCustomWildcard")
			&& Settings::Instance()->Get<std::string>("nativeSigScan.outNormSigWildcard") != "?");

	if (sig.empty())
	{
		Log(ErrorLog, "INPUT IS NOT VALID SIG");
		return;
	}
	// Log(InfoLog, "sig: %s", sig.c_str());
	
	std::vector<int> target_bytes = parse_hex_string(sig);

	auto signature = reinterpret_cast<PBYTE>(target_bytes.data());
	std::vector<char> maskV;
	for (int i = 0; i < sig.length(); i++)
	{
		if (sig[i] == ' ')
			continue;
		if (sig[i] == '?')
		{
			if (i + 1 >= sig.length())
			{
				Log(ErrorLog, "Signature ending with wildcard!");
				return;
			}
			maskV.push_back('?');
			if (sig[i + 1] == '?')
				i++;
		}
		else
		{
			if (!isxdigit(sig[i]) || sig[i + 1] == ' ' || sig[i + 1] == '?')
			{
				Log(ErrorLog, "Signature malformed!");
				return;
			}
			maskV.push_back('x');
			i++;
		}
	}
	auto mask = reinterpret_cast<PBYTE>(maskV.data());
	mask[maskV.size()] = '\0';
	Log(InfoLog, "mask: %s", mask);

	auto mem_segments = view->GetSegments();
	if (mem_segments.size() > 0)
	{
		Log(InfoLog, "Mem Segments: %i", mem_segments.size());
		Log(InfoLog, "Scan Start: 0x%llx", mem_segments[0]->GetStart());
		Log(InfoLog, "Scan End: 0x%llx", mem_segments[mem_segments.size() - 1]->GetEnd() - 1);
	}
	else
	{
		Log(InfoLog, "Scan Start: 0x%llx", view->GetStart());
		Log(InfoLog, "Scan End: 0x%llx", view->GetEnd() - 1);
	}

	auto CompareByteArray = [&](PBYTE data, PBYTE signature, PBYTE mask, int sigLength, uint64_t offset = 0) -> bool {
		int iSig = 0;
		for (; iSig < sigLength; ++iSig, ++signature, ++data, ++mask)
		{
			if (*mask != 'x')
				continue;
			if (*data != *signature)
				return false;
		}
		return true;
	};

	auto FindSignature =
		[&](uint64_t start, uint64_t imageSize, PBYTE signature, int sigLength, PBYTE mask) -> uint64_t {
		BYTE First = signature[0];
		PBYTE base;
		base = new byte[imageSize];

		auto lenRead = view->Read(base, start, imageSize);
		if (lenRead != imageSize)
			Log(WarningLog, "Could not read full segment memory! %i <> %i", imageSize, lenRead);

		uint64_t offset = reinterpret_cast<uint64_t>(base);
		PBYTE Max = base + imageSize - sigLength;

		int i = 0;
		for (; base < Max; ++base, ++i)
		{
			if (*base != First)
				continue;
			if (CompareByteArray(base, signature, mask, sigLength, reinterpret_cast<uint64_t>(base) - offset + start))
				return reinterpret_cast<uint64_t>(base) - offset + start;
		}
		if (lenRead < (i + sigLength))
			Log(WarningLog, "Could not search full segment memory! %i <> %i", lenRead, i + sigLength);

		return NULL;
	};

	Log(InfoLog, "-- NATIVE SIGSCAN START --");
	uint64_t next_found_at = NULL;
	bool next_found = false;

	// iterate through all mem segments
	if (mem_segments.size() > 0)
	{
		for (int i = 0; i < mem_segments.size(); i++)
		{
			uint64_t mem_start = mem_segments[i]->GetStart();
			uint64_t scan_start = mem_start;
			uint64_t mem_size = mem_segments[i]->GetEnd() - mem_start;
			while (true)
			{
				uint64_t found_at = FindSignature(
					scan_start, mem_size - (scan_start - mem_start), signature, target_bytes.size(), mask);
				if (found_at > 0)
				{
					Log(InfoLog, "\tFOUND SIG AT 0x%llx", found_at);
					scan_start = found_at + 1;
				}
				else
				{
					break;
				}
			}
		}
	}
	else
	{
		uint64_t mem_start = view->GetStart();
		uint64_t scan_start = mem_start;
		uint64_t mem_size = view->GetEnd() - mem_start;
		while (true)
		{
			uint64_t found_at =
				FindSignature(scan_start, mem_size - (scan_start - mem_start), signature, target_bytes.size(), mask);
			if (found_at > 0)
			{
				Log(InfoLog, "\tFOUND SIG AT 0x%llx", found_at);
				scan_start = found_at + 1;
			}
			else
			{
				break;
			}
		}
	}

	if (Settings::Instance()->Get<bool>("nativeSigScan.navigateToNextResultAfterSearch") && next_found_at != NULL)
	{
		view->Navigate(view->GetFile()->GetCurrentView(), next_found_at);
	}

	Log(InfoLog, "-- NATIVE SIGSCAN END --");
}

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		PluginCommand::RegisterForRange("Native SigScan\\Create NORM sig from range",
			"Create SIGNATURE IN FORMAT '49 28 15 ? ? 30'.",
			[](BinaryView* view, uint64_t start, uint64_t length) { create_sig(view, start, length, NORM); });
		PluginCommand::RegisterForRange("Native SigScan\\Create CODE sig from range",
			"Create SIGNATURE IN FORMAT '\"\\x49\\x28\\x15\\x00\\x00\\x30\", \"xxx??x\"'.",
			[](BinaryView* view, uint64_t start, uint64_t length) { create_sig(view, start, length, CODE); });
		PluginCommand::Register("Native SigScan\\Find NORM sig",
			"Find SIGNATURE in current binary (FORMAT '49 28 15 ? ? 30' OR '49 28 15 ?? ?? 30').",
			[](BinaryView* view) { find_sig(view, NORM); });
		PluginCommand::Register("Native SigScan\\Find CODE sig",
			"Find SIGNATURE in current binary (FORMAT '\"\\x49\\x28\\x15\\x00\\x00\\x30\", \"xxx??x\"').",
			[](BinaryView* view) { find_sig(view, CODE); });

		auto settings = Settings::Instance();
		settings->RegisterGroup("nativeSigScan", "Native SigScan");
		settings->RegisterSetting("nativeSigScan.outNormSigWildcard",
			R"~({
                        "title": "Custom wildcard",
                        "type": "string",
                        "default": "?",
	                    "description": "Wildcard character(s) used when creating NORM patterns."
	                    })~");
		settings->RegisterSetting("nativeSigScan.inNormSigScanCustomWildcard",
			R"~({
                        "title": "Scan for custom wildcard",
                        "type": "boolean",
                        "default": true,
	                    "description": "Option to scan for custom wildcards when finding NORM patterns (only used if default wildcard is changed), ideally should be set to false if custom wildcard can be a regular byte found in disassembly (0x00-0xFF)."
	                    })~");
		settings->RegisterSetting("nativeSigScan.navigateToNextResultAfterSearch",
			R"~({
                        "title": "Navigate to the closest result",
                        "type": "boolean",
                        "default": false,
	                    "description": "Option to automatically navigate the current view to the closest result relative to the current offset (goes for the closest greater offset or the closest smaller if no greater found)."
	                    })~");

		Log(InfoLog, "BINJA NATIVE SIGSCAN LOADED");
		return true;
	}
}
