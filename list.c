#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

Data* Data_new(){
	Data *data = NULL;
	data = (Data *)malloc(sizeof(Data));
	if (data != NULL){
		data->name = (char *)malloc(sizeof(char) * 100);
		data->next = NULL;
	}
	return data;
}

void Data_free(Data *data){
	free(data->name);
	free(data->next);
	free(data);
}

Data_List* Data_List_new(){
	Data_List* data_list = NULL;
	data_list = (Data_List *)malloc(sizeof(Data_List));
	if (data_list != NULL){
		data_list->size = 0;
		data_list->head = data_list->tail = NULL;
	}
	return data_list;
}

void Data_List_free(Data_List *data_list){
	Data *data;
	while(data_list->head != NULL){
		data = data_list->head;
		data_list->head = data_list->head->next;
		free(data);
	}
}

int Data_List_append(Data_List *data_list, Data *data){
	if (data == NULL){
		return -1;
	}

	if(data_list->size == 0){
		data_list->head = data_list->tail = data;
	}
	else{
		data_list->tail->next = data;
		data_list->tail = data;
	}

	data_list->size += 1;
	return 0;
}

Data_List* Data_List_new_fp(FILE *fp){
	Data *data, *tmp;
	Data_List *data_list;
	char name[100];

	if(fp == NULL){
		fprintf(stderr, "Cannot open file.\n");
		return NULL;
	}

	if((data_list = Data_List_new()) == NULL){
		fprintf(stderr, "Cannot create Data_List.\n");
		fclose(fp);
		return NULL;
	}

	while(EOF != fscanf(fp, "%s", name)){
		
		if((data = Data_new()) == NULL){
			fprintf(stderr, "Cannot create Data.\n");
			return NULL;
		}
		strcpy(data->name, name);
		if(Data_List_append(data_list, data) == -1){
			fprintf(stderr, "Cannot append to Data_List.\n");
			return NULL;
		}
	}
	fclose(fp);

	return data_list;
}

int Data_List_print(Data_List *data_list){
	Data *data;
	if(data_list == NULL){
		fprintf(stderr, "Cannot access the Data_List. Data_List is NULL.\n");
		return -1;
	}
	
	if((data = data_list->head) == NULL){
		fprintf(stderr, "The Data_List is empty.\n");
		return -1;
	}

	printf("==== List Display ====\n");
	printf("List size: %d\n", data_list->size);
	data = data_list->head;
	while(data != NULL){
		printf("%s ", data->name);
		data = data->next;
	}
	printf("\n==== List Display End ====\n\n");
	//printf("%s\n", data->name);
	return 0;
}

int Data_List_has_name(Data_List *data_list, const char *name){
	Data *data;
	if((data = data_list->head) == NULL){
		return -1;
	}
	while(data != NULL){
		if(strcmp(data->name, name) == 0){
			return 1;
		}
		data = data->next;
	}
	return -1;
}