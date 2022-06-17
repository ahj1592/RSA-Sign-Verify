typedef struct data{
	char *name;
	struct data *next;
}Data;

typedef struct data_list{
	Data *head, *tail;
	int size;
}Data_List;

Data* Data_new();
void Data_free(Data *);
Data_List* Data_List_new();
void Data_List_free(Data_List *);
int Data_List_append(Data_List *, Data *);
Data_List* Data_List_new_fp(FILE *fp);
int Data_List_print(Data_List *);
int Data_List_has_name(Data_List*, const char *);