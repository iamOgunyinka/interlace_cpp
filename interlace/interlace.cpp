#include "pch.h"
#include <fstream>
#include <algorithm>
#include <tclap/CmdLine.h>
#include <tclap/ValueArg.h>
#include "task.hpp"

namespace tc = TCLAP;

namespace interlace
{
	using StringArg = tc::ValueArg<std::string>;
	using IntArg = tc::ValueArg<int>;
	using BooleanArg = tc::SwitchArg;
	using StringList = std::vector<std::string>;

	class FileExistsVisitor : public tc::Visitor
	{
		StringArg &value_arg;
	public:
		FileExistsVisitor( StringArg & v ) : value_arg{ v } {}
		void visit() {
			if( value_arg.isSet() ){
				std::ifstream in_file{ value_arg.getValue() };
				if( !in_file ){
					std::cerr << "File does not exist\n";
					std::exit( -1 );
				}
			}
		}
	};

	struct Argument
	{
		bool no_cidr{ false };
		bool no_colour{ false };
		bool no_bar{ false };
		bool verbose{ false };
		bool silent{ false };

		int num_threads{ 5 };
		int timeout{ 600 }; //in milliseconds

		std::string random;
		std::string target;
		std::string target_list;
		std::string command;
		std::string command_list;
		std::string exclusion;
		std::string exclusion_list;
		std::string proxy_list;
		std::string output;
		std::string port;
		std::string proto;
		std::string real_port;
	};

	Argument get_cmdline_argument( int argc, char**argv, tc::CmdLine & cmd_line )
	{
		StringArg target{ "t", "target", "Specify a target or domain name either in comma format, "
					 "CIDR notation, glob notation, or a single target.", true, "", "string" };
		StringArg target_list{ "tL", "target_list", "Specify a list of targets or domain names.",
			true, "", "filename" };
		StringArg exclusion{ "e", "exclusion", "Specify an exclusion either in comma format, "
					 "CIDR notation, or a single target", false, "", "string" };
		StringArg exclusion_list{ "eL", "exclusion_list", "Specify a list of exclusions.", false, "",
			"filename" };
		IntArg num_threads{ "th", "threads", "Specify the maximum number of threads to "
			"run(DEFAULT:5)", false, 5, "integer" };
		IntArg timeout{ "ti", "timeout", "Command timeout in seconds (DEFAULT:600)", false, 600,
			"integer" };
		StringArg proxy_list{ "x", "proxy_list", "Specify a list of proxies.", false, "", "filename" };
		StringArg command{ "c", "command", "Specify a single command to execute.", true, "", "string" };
		StringArg command_list{ "cL", "command_list", "Specify a list of commands to execute",
			true, "", "filename" };
		StringArg output{ "o", "output", "Specify an output folder variable that can be used "
			"in commands as _output_", false, "", "filename" };
		StringArg port{ "p", "port", "Specify a port variable that can be used in commands as _port_",
			false, "", "integer or range" };
		StringArg proto{ "pr", "proto", "Specify protocols that can be used in commands as _proto_.",
			false, "", "string" };
		StringArg real_port{ "rp", "realport", "Specify a real port variable that can be used in "
			"commands as _realport_", false, "", "string" };
		StringArg random{ "ra", "random", "Specify a directory of files that can be randomly "
			"used in commands as _random_", false, "", "string" };
		BooleanArg no_cidr{ "nr", "no-cidr", "If set then CIDR notation in a target file will not "
			"be automatically be expanded into individual hosts." };
		BooleanArg no_colour{ "nc", "no-colour", "If set then any foreground or background "
			"colours will be stripped out." };
		BooleanArg no_bar{ "nb", "no-bar", "If set then progress bar will be stripped out" };
		BooleanArg verbose{ "v", "verbose", "If set then verbose output will be displayed in "
			"the terminal.", false };
		BooleanArg silent{ "s", "silent", "If set only findings will be displayed and banners "
					 "and other information will be redacted.", false };

		cmd_line.add( num_threads );
		cmd_line.add( timeout );
		cmd_line.add( proxy_list );
		cmd_line.add( output );
		cmd_line.add( port );
		cmd_line.add( proto );
		cmd_line.add( real_port );
		cmd_line.add( random );
		cmd_line.add( no_cidr );
		cmd_line.add( no_colour );
		cmd_line.add( no_bar );

		cmd_line.xorAdd( silent, verbose );
		cmd_line.xorAdd( exclusion, exclusion_list );
		cmd_line.xorAdd( target, target_list );
		cmd_line.xorAdd( command, command_list );
		cmd_line.parse( argc, argv );

		interlace::Argument cmd_arguments{};

		cmd_arguments.num_threads = num_threads.getValue();
		cmd_arguments.timeout = timeout.getValue();
		cmd_arguments.proxy_list = proxy_list.getValue();
		cmd_arguments.output = output.getValue();
		cmd_arguments.port = port.getValue();
		cmd_arguments.proto = proto.getValue();
		cmd_arguments.real_port = real_port.getValue();
		cmd_arguments.random = random.getValue();
		cmd_arguments.no_cidr = no_cidr.getValue();
		cmd_arguments.no_colour = no_colour.getValue();
		cmd_arguments.no_bar = no_bar.getValue();
		cmd_arguments.silent = silent.getValue();
		cmd_arguments.verbose = verbose.getValue();
		cmd_arguments.exclusion = exclusion.getValue();
		cmd_arguments.exclusion_list = exclusion_list.getValue();
		cmd_arguments.command = command.getValue();
		cmd_arguments.command_list = command_list.getValue();
		cmd_arguments.target = target.getValue();
		cmd_arguments.target_list = target_list.getValue();

		return cmd_arguments;
	}

	StringList split_string( std::string const & str, char sep )
	{
		StringList result{};
		int offset = 0;
		int found = str.find( sep, offset );
		while( found != std::string::npos ){
			result.push_back( str.substr( offset, found - offset ) );
			offset = found;
			found = str.find( sep, offset + 1 );
		}
		return result;
	}

	std::string strip( std::string const & str )
	{
		char const *sep = " \n\r\t";
		auto temp = str;
		temp.erase( temp.find_last_not_of( sep ) + 1 ); // rtrim strip
		auto index = temp.find_first_not_of( temp );
		if( index == std::string::npos ) return temp;
		return temp.substr( index ); // return ltrim
	}

	void pre_process_hosts( StringList const & host_ranges, 
		Argument const & argument, StringList& destination )
	{

	}

	StringList process_port( std::string const & arg_port )
	{
		if( arg_port.find( "," ) != std::string::npos ){
			return split_string( arg_port, ',' );
		} else if( arg_port.find( "-" ) != std::string::npos ){
			auto result = split_string( arg_port, '-' );
			int start = std::stoi( result[0] );
			int end = std::stoi( result[1] );
			if( start >= end ) throw std::exception( "Invalid port range" );
			StringList result{};
			while( start <= end ) result.push_back( std::to_string( start++ ) );
			return result;
		}
		return StringList{ arg_port };
	}

	std::vector<Task> process_commands( Argument & argument )
	{
		if( !argument.output.empty() && argument.output.back() == '/' ){
			argument.output.pop_back();
		}

		StringList ports{};
		StringList real_ports{};
		StringList ranges{};
		StringList exclusion_ranges{};
		if( !argument.port.empty() ){
			ports = process_port( argument.port );
		}
		if( !argument.real_port.empty() ){
			real_ports = process_port( argument.real_port );
		}
		if( !argument.target.empty() ){
			ranges.push_back( argument.target );
		} else{
			std::ifstream in_file{ argument.target_list };
			if( !in_file ) throw std::exception( "Unable to open file" );
			std::string line{};
			while( std::getline( in_file, line ) ){
				line = strip( line );
				if( !line.empty() ) ranges.push_back( line );
			}
		}
		if( !argument.exclusion.empty() ){
			exclusion_ranges.push_back( argument.exclusion );
		} else if( !argument.exclusion_list.empty() ){
			std::ifstream in_file{ argument.exclusion_list };
			if( !in_file ) throw std::exception( "Unable to open file" );
			std::string line{};
			while( std::getline( in_file, line ) ){
				line = strip( line );
				if( !line.empty() ) exclusion_ranges.push_back( line );
			}
		}

	}

	void build_queue( Argument & argument )
	{
		auto task_list = process_commands( argument );
	}
}

int main( int argc, char **argv )
{
	std::string const program_description{};
	tc::CmdLine cmd_line{ program_description, ' ', "0.1" };
	try{
		auto arguments = interlace::get_cmdline_argument( argc, argv, cmd_line );
		interlace::build_queue( arguments );
	} catch( tc::ArgException & exception ){
		std::cerr << exception.what() << "\n";
		return -1;
	}
	return 0;
}
