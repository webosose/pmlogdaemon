// Copyright (c) 2007-2019 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

/**
 *********************************************************************
 * @file config.c
 *
 * @brief This file contains the functions to read the PmLog.conf
 * configuration file.
 *
 ***********************************************************************
 */

#include "main.h"

#include <ctype.h>
#include <libgen.h>

#include <glib.h>

#include <pbnjson.h>
#include <PmLogLibPrv.h>

#include "print.h"

/***********************************************************************
 * global configuration settings
 ***********************************************************************/
int             g_numOutputs;
PmLogFile_t     g_outputConfs[ PMLOG_MAX_NUM_OUTPUTS ];

int             g_numContexts;
GTree           *g_contextConfs = NULL;

/***********************************************************************
 * OUTPUT section parsing

    Example configuration section:

        [OUTPUT=kernlog]
        File=/var/log/kern.log
        MaxSize=100K
        Rotations=1

    Required:
        File=/var/log/kern.log

    Optional:
        MaxSize=100K
        Rotations=1
 ***********************************************************************/


typedef struct
{
	char    name[ PMLOG_OUTPUT_MAX_NAME_LENGTH + 1 ];
	char    File[ PATH_MAX ];
	int MaxSize;
	int Rotations;
}
PmLogParseOutput_t;


/**
 * @brief FindOutputByName
 * Look up the named output in the g_outputConfs array.
 *
 * @param outputName  name of output
 * @param indexP index to set to correct value
 *
 * @return the index or -1 if not found.
 */
static const PmLogFile_t *FindOutputByName(const char *outputName, int *indexP)
{
	DbgPrint("%s called with outputName=%s\n",
	         __FUNCTION__, outputName);

	for (int i = 0; i < g_numOutputs; i++)
	{
		const PmLogFile_t  *outputConfP = &g_outputConfs[i];

		if (outputConfP && outputConfP->outputName &&
		        (strcmp(outputConfP->outputName,
		                outputName) == 0))
		{
			if (indexP != NULL)
			{
				*indexP = i;
			}

			return outputConfP;
		}
	}

	if (indexP != NULL)
	{
		*indexP = -1;
	}

	return NULL;
}

/**
 * @brief ConfIntValueOrDefault
 *
 * @param n
 * @param defaultVal
 *
 * @return
 */
inline int ConfIntValueOrDefault(int n, int defaultVal)
{
	return (n == CONF_INT_UNINIT_VALUE) ? defaultVal : n;
}


/**
 * @brief GetTokenToSep
 *
 * @param sP
 * @param token
 * @param tokenBuffSize
 * @param terminators
 * @param terminatorP
 */
static void GetTokenToSep(const char **sP, char *token, size_t tokenBuffSize,
                          const char *terminators, char *terminatorP)
{
	const char     *s;
	size_t          tokenLen;

	s = *sP;
	tokenLen = 0;

	while ((*s != 0) && (strchr(terminators, *s) == NULL))
	{
		if (tokenLen + 1 >= tokenBuffSize)
		{
			/* token truncated */
		}
		else
		{
			token[ tokenLen ] = *s;
			tokenLen++;
		}

		s++;
	}

	token[ tokenLen ] = 0;
	*terminatorP = *s;

	if (*s != 0)
	{
		s++;
	}

	*sP = s;
}


/**
 * @brief ParseOutputInit
 *
 * @param name
 * @param parseOutputP
 *
 * @return
 */
static bool ParseOutputInit(const char *name, PmLogParseOutput_t *parseOutputP)
{
	memset(parseOutputP, 0, sizeof(PmLogParseOutput_t));
	DbgPrint("%s called with name=%s\n",
	         __FUNCTION__, name);

	if (g_numOutputs == 0)
	{
		/* we require that first output be stdlog */
		if (strcmp(PMLOG_OUTPUT_STDLOG, name) != 0)
		{
			DbgPrint("Expected stdlog definition\n");
			return false;
		}
	}

	if (strlen(name) > PMLOG_OUTPUT_MAX_NAME_LENGTH)
	{
		DbgPrint("name : \"%s\"  is longer then %d symbols", name, PMLOG_OUTPUT_MAX_NAME_LENGTH);
	}

	/* need to check that name is valid length and char set */
	strncpy(parseOutputP->name, name, PMLOG_OUTPUT_MAX_NAME_LENGTH);
	parseOutputP->File[ 0 ]     = 0;
	parseOutputP->MaxSize       = CONF_INT_UNINIT_VALUE;
	parseOutputP->Rotations     = CONF_INT_UNINIT_VALUE;

	return true;
}


/**
 * @brief MakeOutputConf
 *
 * This is the constructor for the OutputConf object.  It will
 * convert the values in the PmLogParseOutput_t into a PmLogFile_t
 * object.
 *
 * This method will enforce value formatting and limits restrictions
 *
 * @param parseOutputP the ParseOutput object containing the init values.
 *
 * @return true iff the OutputConf was added to the g_outputConfs array.
 */
static bool MakeOutputConf(PmLogParseOutput_t *parseOutputP)
{
	DbgPrint("%s called with po.name=%s\n",
	         __FUNCTION__, parseOutputP->name);
	PmLogFile_t *outputConfP;
	int i;

	switch (parseOutputP->File[0])
	{
		case 0:
			DbgPrint("%s: File not specified\n", parseOutputP->name);
			return false;

		case '/':
			break;

		default:
			DbgPrint("%s: Expected File full path value\n", parseOutputP->name);
			return false;
	}

	/* Finding output */
	outputConfP = (PmLogFile_t *) FindOutputByName(parseOutputP->name, &i);

	/* Make new one */
	if (NULL == outputConfP)
	{
		DbgPrint("creating output %d for %s\n", g_numOutputs + 1, parseOutputP->name);

		if (g_numOutputs >= PMLOG_MAX_NUM_OUTPUTS)
		{
			DbgPrint("%s: Too many output definitions\n", parseOutputP->name);
			return false;
		}

		outputConfP = &g_outputConfs[g_numOutputs];
		memset(outputConfP, 0, sizeof(PmLogFile_t));
		outputConfP->outputName = g_strdup(parseOutputP->name);
		outputConfP->path = g_strdup(parseOutputP->File);
		outputConfP->maxSize = parseOutputP->MaxSize;
		outputConfP->rotations = parseOutputP->Rotations;
		g_numOutputs++;
	}
	else
	{
		DbgPrint("output %d for %s existing already\n", g_numOutputs + 1,
		         parseOutputP->name);
		return true;
	}

	/*
	 * Note: we are not changing the outputName or
	 * path if this context already existed
	 */

	if (parseOutputP->MaxSize == CONF_INT_UNINIT_VALUE)
	{
		/* not set by conf file - set to default */
		parseOutputP->MaxSize = PMLOG_DEFAULT_LOG_SIZE;
	}
	else
	{
		if (parseOutputP->MaxSize < PMLOG_MIN_LOG_SIZE)
		{
			DbgPrint("%s: Log size must be > 4KB: setting to that minimum\n",
			         parseOutputP->name);
			parseOutputP->MaxSize = PMLOG_MIN_LOG_SIZE;
		}
		else if (parseOutputP->MaxSize > PMLOG_MAX_LOG_SIZE)
		{
			DbgPrint("%s: Log size must be < 64MB: setting to that maximum\n",
			         parseOutputP->name);
			parseOutputP->MaxSize = PMLOG_MAX_LOG_SIZE;
		}
	}

	if (parseOutputP->Rotations == CONF_INT_UNINIT_VALUE)
	{
		/* not set - make default */
		outputConfP->rotations = PMLOG_DEFAULT_LOG_ROTATIONS;
	}
	else
	{
		if (parseOutputP->Rotations < PMLOG_MIN_NUM_ROTATIONS)
		{
			DbgPrint("%s: Rotations must be >= %d: setting to that minimum\n",
			         parseOutputP->name, PMLOG_MIN_NUM_ROTATIONS);
			parseOutputP->Rotations = PMLOG_MIN_NUM_ROTATIONS;
		}
		else if (parseOutputP->Rotations > PMLOG_MAX_NUM_ROTATIONS)
		{
			DbgPrint("%s: Rotations must be between <= %d: setting to that maximum\n",
			         parseOutputP->name, PMLOG_MAX_NUM_ROTATIONS);
			parseOutputP->Rotations = PMLOG_MAX_NUM_ROTATIONS;
		}
	}

	return true;
}

/***********************************************************************
 * OUTPUT section parsing

    Example configuration section:

        [CONTEXT=<global>]
        Rule1=*.*,stdlog
        Rule2=kern.*,kernlog
        Rule3=*.err,errlog
 ***********************************************************************/


typedef struct
{
	/* -1 = all or specific value e.g. LOG_KERN */
	int         facility;

	/* -1 = all or specific value e.g. LOG_ERR */
	int         level;
	bool        levelInvert;

	/* empty = all or specific value */
	char        program[ PMLOG_PROGRAM_MAX_NAME_LENGTH + 1 ];

	/* index of output target */
	int         outputIndex;

	/* false to include, true to omit */
	bool        omitOutput;
}
PmLogParseRule_t;


typedef struct
{
	char              name[ PMLOG_MAX_CONTEXT_NAME_LEN + 1 ];
	int               numRules;
	int               bufferSize;
	int               flushLevel;
	PmLogParseRule_t  rules[ PMLOG_CONTEXT_MAX_NUM_RULES ];
}
PmLogParseContext_t;

/**
 * @brief ParseContextInit
 *
 * Initializer for the Parser's Context object
 *
 * @param name name of the object
 * @param parseContextP the pointer to the object to initialize
 *
 * @return true iff we were able to initialize the object
 */
static bool ParseContextInit
(const char *name, PmLogParseContext_t *parseContextP)
{
	memset(parseContextP, 0, sizeof(PmLogParseContext_t));
	DbgPrint("%s called with name=%s\n",
	         __FUNCTION__, name);

	if (g_numContexts == 0)
	{
		/* we require that first context be the default context */
		if (strcmp(kPmLogDefaultContextName, name) != 0)
		{
			DbgPrint("Expected %s context definition\n", kPmLogDefaultContextName);
			return false;
		}
	}

	if (strlen(name) > PMLOG_MAX_CONTEXT_NAME_LEN)
	{
		DbgPrint("name : \"%s\"  is longer then %d symbols", name, PMLOG_MAX_CONTEXT_NAME_LEN);
	}


	strncpy(parseContextP->name, name, PMLOG_MAX_CONTEXT_NAME_LEN);
	parseContextP->numRules = 0;

	return true;
}


/**
 * @brief ParseContextData
 *
 * @param parseContextP
 * @param key
 * @param val
 *
 * @return true if parsed OK, else set error message.
 */
static bool ParseContextData(
    PmLogParseContext_t *parseContextP, const char *key,
    const char *val)
{
	PmLogParseRule_t       *parseRuleP;
	const char             *s;
	char                    token[ 32 ];
	char                    sep;

	DbgPrint("%s called with key=%s\n", __FUNCTION__, key);

	parseRuleP = &parseContextP->rules[ parseContextP->numRules ];

	/*
	 * value string should be of the form <filter>,<output>
	 * where filter ::= <facility>[.[!]<level>[.<program>]]
	 */
	s = val;

	/* get facility */
	GetTokenToSep(&s, token, sizeof(token), ".,", &sep);

	if (!ParseRuleFacility(token, &parseRuleP->facility))
	{
		DbgPrint("Facility not parsed: '%s'\n", token);
		return false;
	}

	/* get level (optional) */
	if (sep == '.')
	{
		parseRuleP->levelInvert = false;

		if (*s == '!')
		{
			parseRuleP->levelInvert = true;
			s++;
		}

		GetTokenToSep(&s, token, sizeof(token), ".,", &sep);

		if (!ParseRuleLevel(token, &parseRuleP->level))
		{
			DbgPrint("Level not parsed: '%s'\n", token);
			return false;
		}
	}
	else
	{
		parseRuleP->levelInvert = false;
		parseRuleP->level = -1;
	}

	/* get program (optional) */
	if (sep == '.')
	{
		GetTokenToSep(&s, token, sizeof(token), ".,", &sep);

		/*GetTokenToSep() guarantee that
		 * token is null-terminated string
		 * token is not longer then PMLOG_PROGRAM_MAX_NAME_LENGTH
		 */
		(void)memset(parseRuleP->program, '\0', sizeof(parseRuleP->program));
		(void)strncpy(parseRuleP->program, token, sizeof(parseRuleP->program) - 1);
	}
	else
	{
		parseRuleP->program[0] = 0;
	}

	/* we should be at the ',' separator between <filter> and <output> */
	if (sep != ',')
	{
		DbgPrint("Expected ',' after filter\n");
		return false;
	}

	parseRuleP->omitOutput = false;

	if ('-' == *s)
	{
		parseRuleP->omitOutput = true;
		s++;
	}

	GetTokenToSep(&s, token, sizeof(token), ".,", &sep);

	if (FindOutputByName(token, &parseRuleP->outputIndex) == NULL)
	{
		DbgPrint("Output not recognized: '%s'\n", token);
		return false;
	}

	if (sep != 0)
	{
		DbgPrint("Unexpected data after output\n");
		return false;
	}

	parseContextP->numRules++;

	return true;
}


static PmLogContextConf_t *CreateContext(const char *name)
{
	PmLogContextConf_t     *contextConfP;
	gchar *gName = g_strdup(name);
	contextConfP = g_new0(PmLogContextConf_t, 1);

	if (contextConfP == NULL)
	{
		DbgPrint("%s: Failed to malloc\n", __FUNCTION__);
		abort();
	}

	// if SetDefaultConf() is called, ClearConf() will release g_contextConfs.
	if (!g_contextConfs)
	{
		g_contextConfs = g_tree_new_full(char_array_comp_func, NULL, g_free, free);
	}

	contextConfP->contextName = gName;
	g_tree_insert(g_contextConfs, gName, contextConfP);
	g_numContexts = g_tree_nnodes(g_contextConfs);

	return contextConfP;
}


/**
 * @brief MakeContextConf
 *
 * This is the constructor for the ContextConf object.  It will
 * convert the values in the PmLogParseContext_t into a PmLogContextConf_t
 * object.
 *
 * @param parseContextP the ParseContext object containing the init values.
 *
 * @return true iff the ContextConf was added to the g_contextConfs array.
 */
static bool MakeContextConf(PmLogParseContext_t *parseContextP)
{
	PmLogContextConf_t     *contextConfP;

	DbgPrint("parseContext name : %s\n", parseContextP->name);
	contextConfP = g_tree_lookup(g_contextConfs, parseContextP->name);

	if (NULL == contextConfP)
	{
		contextConfP = CreateContext(parseContextP->name);
	}

	/* copy over the rules */
	contextConfP->numRules = parseContextP->numRules;

	for (int i = 0; i < parseContextP->numRules; i++)
	{
		PmLogRule_t *contextRuleP = &contextConfP->rules[i];
		PmLogParseRule_t *parseRuleP = &parseContextP->rules[i];

		contextRuleP->facility      = parseRuleP->facility;
		contextRuleP->level     = parseRuleP->level;
		contextRuleP->levelInvert   = parseRuleP->levelInvert;

		if ('\0' == parseRuleP->program[0])
		{
			g_free(contextRuleP->program);
			contextRuleP->program = NULL;
		}
		else
		{
			contextRuleP->program = g_strdup(parseRuleP->program);
		}

		contextRuleP->outputIndex   = parseRuleP->outputIndex;
		contextRuleP->omitOutput    = parseRuleP->omitOutput;
	}

	/* copy buffer info */
	contextConfP->rb = RBNew(parseContextP->bufferSize, parseContextP->flushLevel);

	return true;
}


/**
 * @brief ClearConf
 * Erases all data in the configuration objects
 * (g_outputConfs and g_contextConfs)
 */
static void ClearConf(void)
{
	for (int i = 0; i < g_numOutputs; i++)
	{
		g_free((char*)g_outputConfs[i].outputName);
		g_outputConfs[i].outputName = NULL;
		g_free((char*)g_outputConfs[i].path);
		g_outputConfs[i].path = NULL;
	}

	if (g_contextConfs != NULL)
	{
		g_tree_destroy(g_contextConfs);
	}

	g_numOutputs = 0;
	g_numContexts = 0;

	memset(&g_outputConfs, 0, sizeof(g_outputConfs));
	g_contextConfs = NULL;
}

/**
 * @brief ParseJsonOutputs
 * Parse the value of "outputs" which is represented in configuration file.
 *
 * @param parsed the parsed object for whole the configuration file.
 * @param file_name file name for configuration file.
 */
bool ParseJsonOutputs(const char *file_name)
{
	bool                 ret = false;
	jvalue_ref           outputs_array;
	jvalue_ref           parsed;
	JSchemaInfo          schemainfo;
	PmLogParseOutput_t   parseOutput;

	memset(&parseOutput, 0x00, sizeof(parseOutput));

	DbgPrint("Current FileName : %s\n", file_name);

	jschema_info_init(&schemainfo, jschema_all(), NULL, NULL);
	parsed = jdom_parse_file(file_name, &schemainfo, DOMOPT_INPUT_NOCHANGE);

	if (!jis_null(parsed))
	{
		ret = jobject_get_exists(parsed, j_cstr_to_buffer("outputs"), &outputs_array);
		if (ret)
		{
			for (int outputsIter = 0; outputsIter < jarray_size(outputs_array); outputsIter++)
			{
				jvalue_ref  outputs = jarray_get(outputs_array, outputsIter);
				if (!jis_null(outputs))
				{
					jvalue_ref  value;
					raw_buffer  name;
					raw_buffer  file;

					int  max_size = CONF_INT_UNINIT_VALUE; // -1
					int  rotations = CONF_INT_UNINIT_VALUE; // -1

					memset(&name, 0x00, sizeof(name));
					memset(&file, 0x00, sizeof(file));

					ret = jobject_get_exists(outputs, j_cstr_to_buffer("name"), &value);
					if (ret)   // found name
					{
						name = jstring_get(value);
						if (name.m_len == 0)
						{
							DbgPrint("jstring_get() failed for context %d in configuration file %s for name\n",
							         outputsIter, file_name);
							ret = false;
						}
						else
						{
							ParseOutputInit(name.m_str, &parseOutput);
						}
					}
					else
					{
						DbgPrint("'name' missing for context %d in configuration file %s\n",
						         outputsIter, file_name);
						jstring_free_buffer(name);
					}

					if (!ret)
					{
						jstring_free_buffer(name);
						continue; // We need to keep parsing for next context.
					}

					ret = jobject_get_exists(outputs, j_cstr_to_buffer("file"), &value);

					if (ret)   // found file
					{
						file = jstring_get(value);

						if (!file.m_str)
						{
							DbgPrint("jstring_get() failed for context %d in configuration file %s for file\n",
							         outputsIter, file_name);
							ret = false;
						}
						else
						{
							strncpy(parseOutput.File, file.m_str, sizeof(parseOutput.File) - 1);
						}
					}
					else
					{
						DbgPrint("'file' missing for context %d in cofiguration file %s\n", outputsIter,
						         file_name);
					}

					if (!ret)   // name and file are mandatory field
					{
						jstring_free_buffer(name);
						jstring_free_buffer(file);
						continue; // We need to keep parsing for next context.
					}

					ret = jobject_get_exists(outputs, j_cstr_to_buffer("maxSize"), &value);

					if (ret)   // found maxSize
					{
						if (jnumber_get_i32(value, &max_size) != CONV_OK)
						{
							DbgPrint("jstring_get() failed for context %d in configuration file %s for maxSize\n",
							         outputsIter, file_name);
						}
						else
						{
							max_size *= 1024; // Kilobytes
						}
					}
					else
					{
						DbgPrint("'maxSize' missing for context %d in configuration file %s\n",
						         outputsIter, file_name);
					}

					parseOutput.MaxSize = max_size;

					ret = jobject_get_exists(outputs, j_cstr_to_buffer("rotations"), &value);

					if (ret)   // found rotations
					{
						if (jnumber_get_i32(value, &rotations) != CONV_OK)
						{
							DbgPrint("%s: context %d: file %s: jstring_get() failed "
							         "for name\n", __func__, outputsIter, file_name);
						}
					}
					else
					{
						DbgPrint("'rotations' missing for context %d in configuration file %s\n",
						         outputsIter, file_name);
					}

					parseOutput.Rotations = rotations;

					/* create new PmLogOuputConf_t object */
					if (!MakeOutputConf(&parseOutput))
					{
						DbgPrint("MakeOutputConf() failed in %s\n", file_name);
						ret = false;
					}

					jstring_free_buffer(name);
					jstring_free_buffer(file);

					if (!ret)
					{
						break;
					}
				} // if current entry in outputs array is valid
			} // for loop for traversing outputs array
		}
		else
		{
			DbgPrint("invalid outputs in %s\n", file_name);
		}
	}
	else
	{
		DbgPrint("unable to parse %s\n", file_name);
	}

	// If the parsing for default.conf is failed, then set as default
	char* file_name_cpy = strdup(file_name);
	if ((!strcmp("default.conf", basename(file_name_cpy))) && !ret)
	{
		DbgPrint("outputs parsing was failed in configuration file %s, setting as default\n",
		         file_name);
		SetDefaultConf();
	}

	free(file_name_cpy);
	j_release(&parsed);

	DbgPrint("\n");

	return ret;
}

/**
 * @brief ParseJsonContexts
 * Parse the value of "contexts" which is represented in configuration file.
 *
 * @param parsed the parsed object for whole the configuration file.
 * @param file_name file name for configuration file.
 */
bool ParseJsonContexts(const char *file_name)
{
	bool                 ret = false, optional_ret = false;
	jvalue_ref           contexts_array;
	jvalue_ref           rule_array;
	jvalue_ref           parsed;
	JSchemaInfo          schemainfo;
	PmLogParseContext_t  parseContext;

	jschema_info_init(&schemainfo, jschema_all(), NULL, NULL);
	parsed = jdom_parse_file(file_name, &schemainfo, DOMOPT_INPUT_NOCHANGE);

	if (!jis_null(parsed))
	{
		ret = jobject_get_exists(parsed, j_cstr_to_buffer("contexts"), &contexts_array);

		if (ret)   // found contexts
		{
			for (int contextsIter = 0; contextsIter < jarray_size(contexts_array); contextsIter++)
			{
				jvalue_ref  context;
				jvalue_ref  value;
				raw_buffer  name;
				int         buffer = 1;
				raw_buffer  flush;

				memset(&name, 0x00, sizeof(name));
				memset(&flush, 0x00, sizeof(flush));

				memset(&parseContext, 0x00, sizeof(parseContext));

				context = jarray_get(contexts_array, contextsIter);

				if (!jis_null(context))
				{

					ret = jobject_get_exists(context, j_cstr_to_buffer("name"), &value);

					if (ret)   //found name
					{
						name = jstring_get(value);

						if (!name.m_str)
						{
							DbgPrint("jstring_get() failed for context %d in configuration file %s for name\n",
							         contextsIter, file_name);
							ret = false;
						}
						else
						{
							ParseContextInit(name.m_str, &parseContext);
						}

					}
					else
					{
						DbgPrint("'name' missing for context %d in configuration file %s\n",
						         contextsIter, file_name);
					}

					if (!ret)   // name is a mandatory field.
					{
						jstring_free_buffer(name);
						continue; // We need to keep parsing for next context.
					}

					ret = jobject_get_exists(context, j_cstr_to_buffer("rules"), &rule_array);

					if (ret)   // found rules
					{

						char                 finalString[32] = {0};
						char                 ruleName[32] = {0};

						for (int rulesIter = 0; rulesIter < jarray_size(rule_array); rulesIter++)
						{

							raw_buffer  filter;
							raw_buffer  output;
							jvalue_ref  rules;

							memset(&filter, 0x00, sizeof(filter));
							memset(&output, 0x00, sizeof(output));

							rules = jarray_get(rule_array, rulesIter);
							ret = jobject_get_exists(rules, j_cstr_to_buffer("filter"), &value);

							if (ret)   // found filter
							{
								filter = jstring_get(value);

								if (!filter.m_str)
								{
									DbgPrint("jstring_get() failed for context %d in configuration file %s for filter\n",
									         rulesIter, file_name);
									ret = false;
								}
							}
							else
							{
								DbgPrint("'filter' missing for context %d in configuration file %s\n",
								         rulesIter, file_name);
							}

							if (!ret)   // filter is a mandatory field
							{
								jstring_free_buffer(filter);
								continue;
							}

							ret = jobject_get_exists(rules, j_cstr_to_buffer("output"), &value);

							if (ret)   // found output
							{
								output = jstring_get(value);

								if (!output.m_str)
								{
									DbgPrint("jstring_get() failed for context %d in configuration file %s for output\n",
									         rulesIter, file_name);
									ret = false;
								}
							}
							else
							{
								DbgPrint("'output' missing for rule %d in cofiguration file %s\n", rulesIter,
								         file_name);
							}

							if (!ret)   // output is a mandatory field
							{
								jstring_free_buffer(filter);
								jstring_free_buffer(output);
								continue;
							}

							/* Make Rule's name and value. */
							snprintf(ruleName, sizeof(ruleName), "Rule%d", rulesIter + 1);

							if (filter.m_len > 0 && output.m_len > 0)
							{
								snprintf(finalString, sizeof(finalString), "%s,%s", filter.m_str, output.m_str);
							}

							if (!ParseContextData(&parseContext, ruleName, finalString))
							{
								DbgPrint("ParseContextData() failed %s in cofiguration file %s\n", ruleName,
								         file_name);
								ret = false;
							}

							jstring_free_buffer(filter);
							jstring_free_buffer(output);

							if (!ret)
							{
								break;
							}
						} // for loop for traversing rules array
					}
					else
					{
						DbgPrint("invalid rules in %s\n", file_name);
					} // if rules is valid

					optional_ret = jobject_get_exists(context, j_cstr_to_buffer("bufferSize"),
					                                  &value);

					if (optional_ret)   // found bufferSize
					{
						if (jnumber_get_i32(value, &buffer) != CONV_OK)
						{
							DbgPrint("jstring_get() failed for context %d in configuration file %s for bufferSize\n",
							         contextsIter, file_name);
						}
						else
						{
							parseContext.bufferSize = buffer * 1024;
						}
					} // no else, It is a optional field.

					optional_ret = jobject_get_exists(context, j_cstr_to_buffer("flushLevel"),
					                                  &value);

					if (optional_ret)   //found flushLevel
					{
						flush = jstring_get(value);

						if (!flush.m_str)
						{
							DbgPrint("jstring_get() failed for context %d in configuration file %s for flushLevel\n",
							         contextsIter, file_name);
						}
						else
						{
							if (!ParseLevel(flush.m_str, &(parseContext.flushLevel)))
							{
								DbgPrint("Couldn't parse flushLevel %d\n", contextsIter);
							}
						}
					}

					/* create new PmLogContextConf_t object */
					if (ret)
					{
						MakeContextConf(&parseContext);
					}

				} // if current entry in contexts array is valid

				jstring_free_buffer(name);
				jstring_free_buffer(flush);

				if (!ret)
				{
					break;
				}
			} // for loop for traversing contexts array
		}
		else
		{
			DbgPrint("invalid contexts in %s\n", file_name);
		}
	}
	else
	{
		DbgPrint("unable to parse %s\n", file_name);
	}

	// If the parsing for default.conf is failed, then set as default
	if ((!strcmp("default.conf", (const char *) basename((char *)file_name))) &&
	        !ret)
	{
		DbgPrint("contexts parsing was failed in configuration file %s, setting as default\n",
		         file_name);
		SetDefaultConf();
	}

	j_release(&parsed);

	DbgPrint("\n");

	return ret;
}

/**
 * @brief SetDefaultConf
 */
void SetDefaultConf(void)
{
	PmLogFile_t         *outputConfP;
	PmLogContextConf_t  *contextConfP;
	PmLogRule_t         *contextRuleP;

	DbgPrint("Setting default config\n");

	ClearConf();

	outputConfP = &g_outputConfs[ 0 ];

	outputConfP->outputName     = g_strdup(PMLOG_OUTPUT_STDLOG);
	outputConfP->path           = g_strdup(DEFAULT_LOG_FILE_PATH);
	outputConfP->maxSize        = PMLOG_DEFAULT_LOG_SIZE;
	outputConfP->rotations      = PMLOG_DEFAULT_LOG_ROTATIONS;

	g_numOutputs = 1;

	if (g_contextConfs)
	{
		contextConfP = g_tree_lookup(g_contextConfs, kPmLogDefaultContextName);
		if (!contextConfP)
		{
			contextConfP = CreateContext(kPmLogDefaultContextName);
		}
	}
	else
	{
		contextConfP = CreateContext(kPmLogDefaultContextName);
	}

	contextRuleP = &contextConfP->rules[ 0 ];

	contextRuleP->facility      = -1;
	contextRuleP->level         = -1;
	contextRuleP->levelInvert   = false;
	g_free(contextRuleP->program);
	contextRuleP->program = NULL;
	contextRuleP->outputIndex   = 0;
	contextRuleP->omitOutput    = false;

	contextConfP->numRules = 1;
}
