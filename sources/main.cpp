#include "yara/yara.hpp"
#include "pyscho/pyscho.hpp"

#include <args/args.hxx>
#include <chrono>
#include <spdlog/spdlog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define _VERSION "0.0.1"
#define _NAME "Exorcise: Malware Analysis Engine"
#define _DESCRIPTION "The Exorcise: Malware Analysis engine is a powerful post-incident malware analysis tool, known for its ability to quickly scan for ransomware and detect over 100 distinct malware families within seconds. This cutting-edge tool serves as a guardian against digital threats, offering exceptional efficiency and accuracy in post-incident analysis."

bool is_file_valid(const std::string &path)
{
	struct stat fileInfo;
	if (stat(path.c_str(), &fileInfo) != 0)
	{
		return false; // Erro ao obter informações do arquivo
	}

	return S_ISREG(fileInfo.st_mode); // Verifica se é um arquivo regular
}

int main(int argc, char **argv)
{
	args::ArgumentParser parser(_NAME, _DESCRIPTION);

	// Yara group
	args::Group Yara(parser, "Yara Options:");
	args::ValueFlag<std::string> rules(Yara, "rules", "The folder or file containing Yara rules", {'r', "rules"});
	args::ValueFlag<std::string> path(Yara, "path", "The path to analyze (folder or file)", {'p', "path"});
	args::Flag folder(Yara, "folder", "Analyze as a folder of Yara rules (use with -r)", {'f', "folder"});
	args::Flag verbose(Yara, "verbose", "Enable verbose path analysis", {"verbose"});

	// Driver Pyscho group
	args::Group Pyscho(parser, "Driver Pyscho Options:");
	args::Flag is_driver_installed(Pyscho, "is_driver_installed", "Verify this driver pyscho is installed ", {"ispyscho"});
	args::Flag connect_driver(Pyscho, "connect_driver", "Connect driver interface ", {"connect-pyscho"});

	args::HelpFlag help(parser, "help", "Display this help menu", {'h', "help"});
	args::Flag version(parser, "version", "Version Exorcise", {'v', "version"});

	try
	{
		parser.ParseCLI(argc, argv);

		// group yara options
		if (rules)
		{
			spdlog::info("Yara : Collecting signatures from the folder {}", args::get(rules).c_str());
			YaraAnalysis::IYara *yara = new YaraAnalysis::Yara(args::get(rules).c_str());

			const std::string &path_for_file = args::get(path);

			std::chrono::_V2::system_clock::time_point start = std::chrono::high_resolution_clock::now();

			if (folder)
			{
				spdlog::info("Yara : Scanning Folders '{}' ...", path_for_file);
				yara->scan_folder(path_for_file, SCAN_FLAGS_FAST_MODE, _DEFAULT_SCAN_FUNCTION, verbose);
			}
			else
			{
				if (is_file_valid(path_for_file))
				{
					spdlog::info("Yara : Scanning File '{}'", path_for_file);
					yara->scan_file(path_for_file, SCAN_FLAGS_FAST_MODE, _DEFAULT_SCAN_FUNCTION, verbose);
				}
				else
				{
					spdlog::error("Failed to open file '{}'  Please ensure that the folder exists and has the necessary permissions.", path_for_file);
					return 1;
				}
			}
			std::chrono::_V2::system_clock::time_point stop = std::chrono::high_resolution_clock::now();

			std::chrono::microseconds duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
			spdlog::info("Time elapsed: {}  microseconds.", duration.count());

			delete yara;
		}

		// group pyscho options
		if (is_driver_installed)
		{
			DriverPyscho::IPyscho *pyscho = new DriverPyscho::Pyscho();
			delete pyscho;
		}
		if (connect_driver)
		{
			DriverPyscho::IPyscho *pyscho = new DriverPyscho::Pyscho();

			pyscho->connect_driver();

			delete pyscho;
		}

		// all groups
		if (version)
		{
			std::cout << _NAME << " " << _VERSION << std::endl;
			std::cout << "Copyright (C) 2023 Moblog Security Researchers" << std::endl;
			std::cout << "License: All rights reserved <PsiCoShield>" << std::endl;
			std::cout << "For more information, visit: <https://moblog.in>" << std::endl;
		}
	}
	catch (args::Help)
	{
		std::cout << parser;
		return 0;
	}
	catch (args::ParseError e)
	{
		std::cerr << e.what() << "\n";
		std::cerr << parser;
		return 1;
	}
	catch (args::ValidationError e)
	{
		std::cerr << e.what() << "\n";
		std::cerr << parser;
		return 1;
	}

	return 0;
}
