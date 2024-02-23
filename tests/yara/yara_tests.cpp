#include <gtest/gtest.h>
#include "yara/yara.hpp"
#include <yara/rules.h>
#include "yara/iyara.hpp"
#include <yara/error.h>

YaraAnalysis::Yara::CALLBACK_ARGS data_user;

class YaraTests : public ::testing::Test
{
protected:
    YaraAnalysis::IYara *yara_instance = new YaraAnalysis::Yara("rules");
};

YR_CALLBACK_FUNC scan_file(YR_SCAN_CONTEXT *context,
                           int message,
                           void *message_data,
                           void *user_data)
{
    data_user = *(YaraAnalysis::Yara::CALLBACK_ARGS *)user_data;
    if (CALLBACK_MSG_RULE_MATCHING)
      (*(YaraAnalysis::Yara::CALLBACK_ARGS *)user_data).current_count++;

    return 0;
}

TEST_F(YaraTests, ScanFile)
{
    const char *expected_file_name = "rules/teste.yar";
    yara_instance->scan_file(expected_file_name, SCAN_FLAGS_FAST_MODE, reinterpret_cast<YR_CALLBACK_FUNC>(scan_file));

    ASSERT_EQ(strcmp(data_user.file_path, expected_file_name), 0);
    ASSERT_EQ(data_user.current_count, 1);
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}