/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (C) 2017-2018 Michael Drake <tlsa@netsurf-browser.org>
 */

/**
 * \file
 * \brief Free data structures created by the CYAML load functions.
 *
 * As described in the public API for \ref cyaml_free(), it is preferable for
 * clients to write their own free routines, tailored for their data structure.
 *
 * Recursion and stack usage
 * -------------------------
 *
 * This generic CYAML free routine is implemented using recursion, rather
 * than iteration with a heap-allocated stack.  This is because recursion
 * seems less bad than allocating within the free code, and the stack-cost
 * of these functions isn't huge.  The maximum recursion depth is of course
 * bound by the schema, however schemas for recursively nesting data structures
 * are unbound, e.g. for a data tree structure.
 */

#include <stdbool.h>
#include <assert.h>
#include <string.h>

#include "data.h"
#include "util.h"
#include "mem.h"

/**
 * Free stack entry.
 *
 * This allows inspection back up the call stack; the parent pointers form
 * a linked list.
 */
typedef struct cyaml_free_stack {
	/** Schema for value to be freed. */
	const cyaml_schema_value_t * const schema;
	/** Parent free stack entry pointer. */
	const struct cyaml_free_stack * const parent;
	/** Data for value to be freed. */
	uint8_t *data;
} cyaml_free_stack_t;

/**
 * Internal function for freeing a CYAML-parsed data structure.
 *
 * \param[in]  cfg     The client's CYAML library config.
 * \param[in]  parent  Parent entry on the free stack.
 * \param[in]  count   If data is of type \ref CYAML_SEQUENCE, this is the
 *                     number of entries in the sequence.
 */
static void cyaml__free_value(
		const cyaml_config_t *cfg,
		cyaml_free_stack_t *parent,
		uint64_t count);

/**
 * Internal function for freeing a CYAML-parsed sequence.
 *
 * \param[in]  cfg     The client's CYAML library config.
 * \param[in]  parent  Parent entry on the free stack.
 * \param[in]  count   The sequence's entry count.
 */
static void cyaml__free_sequence(
		const cyaml_config_t *cfg,
		const cyaml_free_stack_t *parent,
		uint64_t count)
{
	uint32_t data_size = parent->schema->sequence.entry->data_size;

	cyaml__log(cfg, CYAML_LOG_DEBUG,
			"Free: Freeing sequence with count: %u\n", count);

	if (parent->schema->sequence.entry->flags & CYAML_FLAG_POINTER) {
		data_size = sizeof(parent->data);
	}

	for (unsigned i = 0; i < count; i++) {
		cyaml_free_stack_t stack = {
			.schema = parent->schema->sequence.entry,
			.data = parent->data + data_size * i,
			.parent = parent,
		};
		cyaml__log(cfg, CYAML_LOG_DEBUG,
				"Free: Freeing sequence entry: %u\n", i);
		cyaml__free_value(cfg, &stack, 0);
	}
}

/**
 * Internal function for freeing a CYAML-parsed mapping.
 *
 * \param[in]  cfg     The client's CYAML library config.
 * \param[in]  parent  Parent entry on the free stack.
 */
static void cyaml__free_mapping(
		const cyaml_config_t *cfg,
		const cyaml_free_stack_t *parent)
{
	const cyaml_schema_field_t *schema = parent->schema->mapping.fields;

	while (schema->key != NULL) {
		cyaml_free_stack_t stack = {
			.data = parent->data + schema->data_offset,
			.schema = &schema->value,
			.parent = parent,
		};
		uint64_t count = 0;
		cyaml__log(cfg, CYAML_LOG_DEBUG,
				"Free: Freeing key: %s (at offset: %u)\n",
				schema->key, (unsigned)schema->data_offset);
		if (schema->value.type == CYAML_SEQUENCE) {
			cyaml_err_t err;
			count = cyaml_data_read(schema->count_size,
					parent->data + schema->count_offset,
					&err);
			if (err != CYAML_OK) {
				return;
			}
		}
		cyaml__free_value(cfg, &stack, count);
		schema++;
	}
}

/**
 * Read union discriminant from client data.
 *
 * \param[in]  cfg               The client's CYAML library config.
 * \param[in]  schema            A schema to search for union discriminant.
 * \param[in]  union_disc_field  Field name for union discriminant.
 * \param[in]  data              Pointer to client data for value at schema.
 * \param[in]  idx_out           Returns union discriminant value on success.
 * \return CYAML_OK on success, CYAML_ERR_UNION_DISC_NOT_FOUND if the given
 *         schema entry did not contain a discriminant, or appropriate error
 *         otherwise.
 */
static inline cyaml_err_t cyaml__read_union_discriminant(
		const cyaml_config_t *cfg,
		const cyaml_schema_value_t *schema,
		const char *union_disc_field,
		const uint8_t *data,
		uint64_t *idx_out)
{
	uint16_t idx;

	if (schema->type != CYAML_MAPPING) {
		return CYAML_ERR_UNION_DISC_NOT_FOUND;
	}

	idx = cyaml__get_mapping_field_idx(cfg, schema, union_disc_field);
	if (idx != CYAML_FIELDS_IDX_NONE &&
	    (schema->mapping.fields + idx)->value.type == CYAML_ENUM) {
		cyaml_err_t err;
		const cyaml_schema_field_t *disc = schema->mapping.fields + idx;
		uint64_t union_discriminant = cyaml_data_read(
				disc->value.data_size,
				data + disc->data_offset, &err);
		if (err != CYAML_OK) {
			return err;
		};

		*idx_out = (uint16_t)union_discriminant;
		return CYAML_OK;
	}

	return CYAML_ERR_UNION_DISC_NOT_FOUND;
}

/**
 * Internal function for freeing a CYAML-parsed union.
 *
 * \param[in]  cfg     The client's CYAML library config.
 * \param[in]  parent  Parent entry on the free stack.
 */
static void cyaml__free_union(
		const cyaml_config_t *cfg,
		const cyaml_free_stack_t *parent)
{
	const cyaml_schema_field_t *schema = parent->schema->mapping.fields;
	uint64_t count = 0;

	if (parent->schema->mapping.union_discriminant != NULL) {
		for (const cyaml_free_stack_t *p = parent;
				p != NULL; p = p->parent) {
			cyaml_err_t err;
			uint64_t idx;

			err = cyaml__read_union_discriminant(cfg, p->schema,
				parent->schema->mapping.union_discriminant,
				parent->data, &idx);
			if (err == CYAML_ERR_UNION_DISC_NOT_FOUND) {
				continue;
			} else if (err != CYAML_OK) {
				return;
			}

			if (idx < cyaml__get_mapping_field_count(schema)) {
				schema += idx;
			}

			break;
		}
	}

	cyaml__log(cfg, CYAML_LOG_DEBUG,
			"Free: Freeing union of type: %s (at offset: %u)\n",
			schema->key, (unsigned)schema->data_offset);

	if (schema->value.type == CYAML_SEQUENCE) {
		cyaml_err_t err;
		count = cyaml_data_read(schema->count_size,
				parent->data + schema->count_offset,
				&err);
		if (err != CYAML_OK) {
			return;
		}
	}

	{
		cyaml_free_stack_t stack = {
			.data = parent->data + schema->data_offset,
			.schema = &schema->value,
			.parent = parent,
		};
		cyaml__free_value(cfg, &stack, count);
	}
}

/* This function is documented at the forward declaration above. */
static void cyaml__free_value(
		const cyaml_config_t *cfg,
		cyaml_free_stack_t *parent,
		uint64_t count)
{
	if (parent->schema->flags & CYAML_FLAG_POINTER) {
		parent->data = cyaml_data_read_pointer(parent->data);
		if (parent->data == NULL) {
			return;
		}
	}

	if (parent->schema->type == CYAML_MAPPING) {
		cyaml__free_mapping(cfg, parent);

	} else if (parent->schema->type == CYAML_UNION) {
		cyaml__free_union(cfg, parent);

	} else if (parent->schema->type == CYAML_SEQUENCE ||
	           parent->schema->type == CYAML_SEQUENCE_FIXED) {
		if (parent->schema->type == CYAML_SEQUENCE_FIXED) {
			count = parent->schema->sequence.max;
		}
		cyaml__free_sequence(cfg, parent, count);
	}

	if (parent->schema->flags & CYAML_FLAG_POINTER) {
		cyaml__log(cfg, CYAML_LOG_DEBUG, "Free: Freeing: %p\n",
				parent->data);
		cyaml__free(cfg, parent->data);
	}
}

/* Exported function, documented in include/cyaml/cyaml.h */
cyaml_err_t cyaml_free(
		const cyaml_config_t *config,
		const cyaml_schema_value_t *schema,
		cyaml_data_t *data,
		unsigned seq_count)
{
	cyaml_free_stack_t stack = {
		.schema = schema,
		.data = (void *)&data,
	};

	if (config == NULL) {
		return CYAML_ERR_BAD_PARAM_NULL_CONFIG;
	}
	if (config->mem_fn == NULL) {
		return CYAML_ERR_BAD_CONFIG_NULL_MEMFN;
	}
	if (schema == NULL) {
		return CYAML_ERR_BAD_PARAM_NULL_SCHEMA;
	}
	cyaml__log(config, CYAML_LOG_DEBUG, "Free: Top level data: %p\n", data);
	cyaml__free_value(config, &stack, seq_count);
	return CYAML_OK;
}
