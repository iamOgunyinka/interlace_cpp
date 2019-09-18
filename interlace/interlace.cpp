#include "pch.h"
#include <fstream>
#include <algorithm>
#include <set>
#include <cassert>
#include <tclap/CmdLine.h>
#include <tclap/ValueArg.h>
#include <fmt/format.h>
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
		std::string command;
		std::string exclusion;
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

		// exclusion and exclusion list are optional, they may both be empty
		if( exclusion.isSet() ){
			cmd_arguments.exclusion = exclusion.getValue();
		} else if( exclusion_list.isSet() ){
			cmd_arguments.exclusion = "``" + exclusion_list.getValue();
		}
		cmd_arguments.command = command.isSet() ? command.getValue() :
			"``" + command_list.getValue();
		cmd_arguments.target = target.isSet() ? target.getValue() :
			"``" + target_list.getValue();

		return cmd_arguments;
	}

	StringList split_string( std::string const & str, char sep )
	{
		StringList result{};
		int offset{}, found = str.find( sep, offset );
		while( found != std::string::npos ){
			result.push_back( str.substr( offset, found - offset ) );
			offset = found;
			found = str.find( sep, offset + 1 );
		}
		return result;
	}

	void strip( std::string & str )
	{
		char const *sep = " \n\r\t";
		str.erase( str.find_last_not_of( sep ) + 1 ); // rtrim strip
		auto const index = str.find_first_not_of( sep );
		if( index == std::string::npos ) return;
		str.erase( 0, index ); //ltrim
	}

	StringList ip_range( unsigned int const ip_start, unsigned int const ip_end )
	{
		unsigned int const ip_1 = ip_start, ip_2 = ip_end;
		
		int const ip1_first_byte = ip_1 >> 24, ip1_second_byte = ( ip_1 >> 16 ) & 0xFF,
			ip1_third_byte = ( ip_1 >> 8 ) & 0xFF, ip1_last_byte = ip_1 & 0xFF;
		
		int const ip2_first_byte = ip_2 >> 24, ip2_second_byte = ( ip_2 >> 16 ) & 0xFF,
			ip2_third_byte = ( ip_2 >> 8 ) & 0xFF, ip2_last_byte = ip_2 & 0xFF;
		
		StringList ip_list{};

		for( int i0 = ip1_first_byte; i0 <= ip2_first_byte; ++i0 ){
			for( int i1 = ip1_second_byte; i1 <= ip2_second_byte; ++i1 ){
				for( int i2 = ip1_third_byte; i2 <= ip2_third_byte; ++i2 ){
					for( int i3 = ip1_last_byte; i3 <= ip2_last_byte; ++i3 ){
						ip_list.push_back( fmt::format( "{}.{}.{}.{}", i0, i1, i2, i3 ) );
					}
				}
			}
		}
		return ip_list;
	}

	StringList cidrs_to_ips( std::string const & ip )
	{
		auto parts = split_string( ip, '.' );
		assert( parts.size() == 4 );
		auto last_part = split_string( parts[3], '/' );
		assert( last_part.size() == 2 );
		parts[3] = last_part[0];
		uint32_t ip_num = std::stoi( parts[0] ) << 24 |
			std::stoi( parts[1] ) << 16 |
			std::stoi( parts[2] ) << 8 |
			std::stoi( parts[3] );
		int mask_bits = std::stoi( last_part[1] );
		unsigned int mask = 0xFFFFFFFF;
		mask <<= ( 32 - mask_bits );
		unsigned int ip_start = ip_num & mask;
		unsigned int ip_end = ip_num | ~mask;
		return ip_range( ip_start, ip_end );
	}

	StringList ip_from_range( std::string const & ip )
	{
		StringList ip_range = split_string( ip, '-' );
		assert( ip_range.size() == 2 );
		auto first_range = split_string( ip_range[0], '.' );
		std::string end_ip{};
		for( int i = 0; i != first_range.size() - 1; ++i ){
			end_ip += ( first_range[i] + "." );
		}
		end_ip += ip_range[1];

		auto ip1 = split_string( ip_range[0], '.' );
		auto ip2 = split_string( end_ip, '.' );
		assert( ip1.size() == 4 && ip2.size() == 4 );

		int const ip1_first_byte = std::stoi( ip1[0] ), ip1_second_byte = std::stoi( ip1[1] ),
			ip1_third_byte = std::stoi( ip1[2] ), ip1_last_byte = std::stoi( ip1[3] );
		int const ip2_first_byte = std::stoi( ip2[0] ), ip2_second_byte = std::stoi( ip2[1] ),
			ip2_third_byte = std::stoi( ip2[2] ), ip2_last_byte = std::stoi( ip2[3] );
		StringList ip_list{};

		for( int i0 = ip1_first_byte; i0 <= ip2_first_byte; ++i0 ){
			for( int i1 = ip1_second_byte; i1 <= ip2_second_byte; ++i1 ){
				for( int i2 = ip1_third_byte; i2 <= ip2_third_byte; ++i2 ){
					for( int i3 = ip1_last_byte; i3 <= ip2_last_byte; ++i3 ){
						ip_list.push_back( fmt::format( "{}.{}.{}.{}", i0, i1, i2, i3 ) );
					}
				}
			}
		}
		return ip_list;
	}


	StringList ip_from_glob( std::string const & glob )
	{
		//TODO
		return StringList{};
	}

	void pre_process_hosts( std::set<std::string> & host_ranges,
		Argument const & argument, StringList& destination )
	{
		for( auto const& h : host_ranges ){
			// remove all spaces
			auto host = h;
			host.erase( std::remove( host.begin(), host.end(), ' ' ), host.end() );
			for( auto const & ip : split_string( host, ',' ) ){
				auto const dot_split = split_string( ip, '.' );
				if( !dot_split.empty() && !dot_split.back().empty() ){
					if( isalpha( dot_split.back()[0] ) ){
						destination.push_back( ip );
						continue;
					}
				}
				if( !argument.no_cidr && ip.find( '/' ) != std::string::npos ){
					auto ip_address = cidrs_to_ips( ip );
					for( auto& address : ip_address )
						destination.push_back( std::move( address ) );
				} else if( ip.find( '-' ) != std::string::npos ){
					auto addresses = ip_from_range( ip );
					for( auto&address : addresses )
						destination.push_back( std::move( address ) );
				} else if( ip.find( '*' ) != std::string::npos ){
					auto addresses = ip_from_glob( ip );
					for( auto&address : addresses )
						destination.push_back( std::move( address ) );
				} else{
					destination.push_back( ip );
				}
			}
		}
	}

	StringList process_port( std::string const & arg_port )
	{
		if( arg_port.find( ',' ) != std::string::npos ){
			return split_string( arg_port, ',' );
		} else if( arg_port.find( '-' ) != std::string::npos ){
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

		StringList ports{}, real_ports{};
		std::set<std::string> ranges{}, exclusion_ranges{};

		if( !argument.port.empty() ){
			ports = process_port( argument.port );
		}
		if( !argument.real_port.empty() ){
			real_ports = process_port( argument.real_port );
		}
		auto is_using_file = []( std::string const & argument ){
			return argument.size() > 1 && argument[0] == '`'
				and argument[1] == '`';
		};

		if( is_using_file( argument.target ) ){
			std::ifstream in_file{ argument.target.substr( 2 ) };
			if( !in_file ) throw std::exception( "Unable to open file" );
			std::string line{};
			while( std::getline( in_file, line ) ){
				strip( line );
				if( !line.empty() ) ranges.insert( std::move( line ) );
			}
		} else{
			ranges.insert( argument.target );
		}
		if( !argument.exclusion.empty() ){
			if( is_using_file( argument.exclusion ) ){
				std::ifstream in_file{ argument.exclusion.substr( 2 ) };
				if( !in_file ) throw std::exception( "Unable to open file" );
				std::string line{};
				while( std::getline( in_file, line ) ){
					strip( line );
					if( !line.empty() ) exclusion_ranges.insert( line );
				}
			} else{
				exclusion_ranges.insert( argument.exclusion );
			}
		}
		StringList targets{};
		pre_process_hosts( ranges, argument, targets );
		pre_process_hosts( exclusion_ranges, argument, targets );
		StringList diff{};
		std::set_difference( targets.cbegin(), targets.cend(), exclusion_ranges.cbegin(),
			exclusion_ranges.cend(), std::back_inserter( diff ) );

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
