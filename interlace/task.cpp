#include "pch.h"
#include "task.hpp"

namespace interlace {
	Task::Task(std::string c) : command{ std::move(c) }
	{
	}


	Task::~Task()
	{
	}


}