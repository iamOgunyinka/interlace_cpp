#pragma once
#include <string>
#include <mutex>

namespace interlace
{
	class Task
	{
		std::string command;
	public:
		Task(std::string c);
		virtual ~Task();
	};

	class TaskBlock : public Task
	{

	};
}