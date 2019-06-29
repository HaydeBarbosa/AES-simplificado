/*
		HAYDE VICTORIA BARBOSA MORENO	
		SECURE DOCUMENTS II
		AES-S MODOS: CTR & CBC
*/

/*
		ACTUALIZACION 07/05/2016
			*Correccion de la funcion deg(): eliminacion de pow
			*Correccion de la funcion multiply(,,): eliminacion de pow
			*Funciones AES (Cifrado y descifrado por bloque)
			
		ACTUALIZACION 14/05/2016
			*Funciones para generar numeros aleatorios enteros en un rango (genera llaves o vectores):
				-CongLineal(rango/0->m-1/, num elementos)
				-CongMult(rango/0->m-1/, num elementos)
				-CongCuad(rango/0->m-1/, num elementos)
			*Implementacion de lectura y escritura de archivos usando buffers
			*Modos de cifrado y descifrado CBC, archivos de cualquier longitud y formato
			*Modo CTR, archivos de cualquier longitud y formato
			
		ACTUALIZACION 22/05/2016
			*Mejoras al modo CTR: creacion del vector de inicializacion y almacenamiento del mismo
			*Mejoras al modo CBC: creacion del vector de inicializacion y almacenamiento del mismo
			*Funciones para generar-leer una llave
					
*/
#include<stdio.h>
#include<stdlib.h>
#include<string.h>


/*DECLARACION DE FUNCIONES*/
int*NibbleSub(int state[], int inverso);
int*AddRoundKey(int state[], int roundkey[]);
int*ShiftRow(int state[]);
int*MixColumns(int state[], int inverso);
int*ExpandKey(int key[]);
int*EncryptAES(int bloque[], int key[]);
int*DecryptAES(int bloque[], int key[]);
int*splitChain(int chain, int trozos);
int*CongLineal(int m, int k);
int*CongMult(int m, int k);
int*CongCuad(int m, int k);
int*VectorInCTR(int m, int k, int fileLen);
int*GenerarLlave(void);

/*S-BOX*/
int sbox[]={9,4,10,11,13,1,8,5,6,2,0,3,12,14,15,7};
int isbox[]={10,5,9,11,1,7,8,15,6,0,2,3,12,4,13,14};

/*CTR para AES-S*/

/*CTR:
	archIn: archivo a leer
	archOut: archivo donde se guardara lo hecho
	vIni: vector de inicializacion
	key: llave para AES-S
	decript: 0 - encriptar, 1 - desencriptar, esta opcion es para tener manejo de archivos con un numero de bytes impar
	*/
	
int*LeerLlave(void)
{
	char temp[50], llave[50], s[2]="*",*token;
	int *reg= malloc(sizeof(int)*4);
	FILE *key;
	int i=0;
	
	printf("Ingrese el nombre de la llave (AES-S): ");
	scanf("%s", &llave);
    strcat(llave, ".key");
    key=fopen(llave, "r");
    fgets(temp, 12, key);
    token = strtok(temp, s);
	while( token != NULL ) 
   	{
    	reg[i]=atoi(token);
    	token = strtok(NULL, s);
    	i++;
   	}
    return reg;
}
	
int*GenerarLlave(void)
{
	char menu, temp[50], llave[50], s[2]="*",*token;
	int *reg= malloc(sizeof(int)*4);
	FILE *key;
	int i=0, aux=17;

    menu = '\000';
	system("cls");
	printf("Generar llave AES-S:\n\n");
	printf("1) Nueva llave\n");
	printf("2) Nueva llave aleatoria\n\n");
	printf("Ingrese la opcion deseada: ");

	gets(temp);
	if(temp!="") menu=temp[0];

	/*switch para el menu*/
	switch (menu)
	{
		case '1':
			system("cls");
			printf("Ingrese un nombre para la llave: ");
			scanf("%s", &llave);
            strcat(llave, ".key");
            key=fopen(llave, "w");
            for(i=0;i<4;i++)
            {
				while(aux<0 || aux>15)
				{
					printf("\nIngrese el valor %d (entre 0-15): ", i+1);
					scanf("%d", &aux);
				}
				reg[i]=aux;
				fprintf(key, "%d*", aux);
				aux=17;
			}
            fclose(key);
            return reg;
		break;
		case '2':
			system("cls");
			printf("Ingrese un nombre para la llave: ");
			scanf("%s", &llave);
            strcat(llave, ".key");
			key=fopen(llave, "w");
            reg=CongLineal(16, 4);
            for(i=0;i<4;i++) fprintf(key, "%d*", reg[i]);
            fclose(key);
            return reg;
		break;
		
		default:
			GenerarLlave();
		break;
	}
	
}

void CTR(char archIn[], char archOut[], int key[], int decrypt)
{
	unsigned long fileLen, cont;
	char c;
	int i, k=0, n, progreso, cadena=0;
	int *bloqueCT= malloc(sizeof(int)*4), *bloquePT= malloc(sizeof(int)*4), *aux=malloc(sizeof(int)*2);
	int *vector=malloc(sizeof(int)*4), *reg=malloc(sizeof(int)*4);
    FILE *entrada=fopen(archIn, "rb"), *salida=fopen(archOut, "wb");
    
    
    
    fseek(entrada, 0, SEEK_END);
    fileLen=ftell(entrada);//tamaño del buffer
    fseek(entrada, 0, SEEK_SET);
    
    //Estamos encriptando, por lo que creamos el vector IV
    if(decrypt==0)
    {
    	//Creamos el vector de inicializacion:
		vector=CongLineal(16,4);
		i=joinChain(vector, 4);
		n=potencia(2,16);
		while(n-1-fileLen-i<0){vector=CongLineal(16,4);i=joinChain(vector, 4);}
		/*
		printf("\nVector de inicializacion:");
		for(i=0;i<4;i++) printf(" %d, ", vector[i]);
		printf("\n");
		*/
		//Guardo el vector de inicializacion al inicio del archivo
		fprintf(salida, "%c%c", add(vector[0]<<4, vector[1]), add(vector[2]<<4, vector[3]));
	}
	
	if(fileLen%2==1) n=2;
	else n=1;
	
    for(cont=0; cont<fileLen+n; cont++)
    {
		
		if(k==2)
		{
			//recuperamos el vector IV para desencriptar
			if(decrypt==1 && cont==2)
			{
				vector[0]=bloquePT[0];
				vector[1]=bloquePT[1];
				vector[2]=bloquePT[2];
				vector[3]=bloquePT[3];
				/*
				printf("\nVector de inicializacion:");
				for(i=0;i<4;i++) printf(" %d, ", vector[i]);
				printf("\n");
				*/
			}
			//Ya tenemos el vector, desencriptamos
			else
			{
				//for(i=0;i<4;i++) printf("*%d, ", vector[i]);
				bloqueCT=EncryptAES(vector, key);
			
				for(i=0;i<4;i++) bloqueCT[i]=add(bloqueCT[i], bloquePT[i]);
			
				if(decrypt==1 && cont==fileLen)	fprintf(salida, "%c", add(bloqueCT[0]<<4, bloqueCT[1]));
				else fprintf(salida, "%c%c", add(bloqueCT[0]<<4, bloqueCT[1]), add(bloqueCT[2]<<4, bloqueCT[3]));
			
				cadena=0;
				for(i=0;i<4;i++) cadena=add(cadena, vector[i]<<(4*(4-i-1)));
				vector=splitChain(cadena+1, 4);
			}
			k=0;
		}
		
		c=fgetc(entrada);
		aux=splitChain(c, 2);
		if(cont%2==0)
		{
			bloquePT[0]=aux[0];
			bloquePT[1]=aux[1];
		}
		else
		{
			bloquePT[2]=aux[0];
			bloquePT[3]=aux[1];
		}
		
		k++;
	}	
	fclose(salida);
	fclose(entrada);
}


/*CBC para AES-S*/
void EncryptCBC(char archIn[], char archOut[], int key[])
{
	unsigned long fileLen, cont;
	char c;
	int i, k=0, n;
	int *bloqueCT= malloc(sizeof(int)*4), *bloquePT= malloc(sizeof(int)*4), *aux=malloc(sizeof(int)*2);
    FILE *entrada=fopen(archIn, "rb"), *salida=fopen(archOut, "wb");
    
	fseek(entrada, 0, SEEK_END);
    fileLen=ftell(entrada);//tamaño del buffer
    fseek(entrada, 0, SEEK_SET);
    
    //inicializacion de bloqueCT o vector de inicializacion:
	bloqueCT=CongLineal(16,4);
	//Guardo el vector de inicializacion al inicio del archivo
	//for(i=0;i<4;i++) printf("-%d, ", bloqueCT[i]);
	/*
	printf("\nVector de inicializacion:");
	for(i=0;i<4;i++) printf(" %d, ", bloqueCT[i]);
	printf("\n");
	*/
	fprintf(salida, "%c%c", add(bloqueCT[0]<<4, bloqueCT[1]), add(bloqueCT[2]<<4, bloqueCT[3]));

	if(fileLen%2==1) n=2;
	else n=1;
	
    for(cont=0; cont<fileLen+n; cont++)
    {
		if(k==2)
		{
			for(i=0;i<4;i++) bloquePT[i]=add(bloqueCT[i], bloquePT[i]);
			bloqueCT=EncryptAES(bloquePT, key);
			fprintf(salida, "%c%c", add(bloqueCT[0]<<4, bloqueCT[1]), add(bloqueCT[2]<<4, bloqueCT[3]));
			k=0;
		}
		
		c=fgetc(entrada);
		aux=splitChain(c, 2);
		if(cont%2==0)
		{
			bloquePT[0]=aux[0];
			bloquePT[1]=aux[1];
		}
		else
		{
			bloquePT[2]=aux[0];
			bloquePT[3]=aux[1];
		}
		
		k++;
	}	
	fclose(salida);
	fclose(entrada);
}

void DecryptCBC(char archIn[], char archOut[], int key[])
{
	unsigned long fileLen, cont;
	char c;
	int i, n, k=0;
	int *bloqueCT= malloc(sizeof(int)*4), *bloquePT= malloc(sizeof(int)*4), *extra= malloc(sizeof(int)*4), *aux=malloc(sizeof(int)*2);
    FILE *entrada=fopen(archIn, "rb"), *salida=fopen(archOut, "wb");
    
    fseek(entrada, 0, SEEK_END);
    fileLen=ftell(entrada);//tamaño del buffer
    fseek(entrada, 0, SEEK_SET);
    
	if(fileLen%2==1) n=2;
	else n=1;
	
	for(cont=0; cont<fileLen+n; cont++)
    {
		if(k==2)
		{
			//recupero el vector de inicializacion
			if(cont==2)
			{
				extra[0]=bloqueCT[0];
				extra[1]=bloqueCT[1];
				extra[2]=bloqueCT[2];
				extra[3]=bloqueCT[3];
				/*
				printf("\nVector de inicializacion:");
				for(i=0;i<4;i++) printf(" %d, ", extra[i]);
				printf("\n");
				*/
			}
			//desencripto
			bloquePT=DecryptAES(bloqueCT, key);
			for(i=0;i<4;i++) bloquePT[i]=add(bloquePT[i], extra[i]);
			
			if(n==1 && cont==fileLen) fprintf(salida, "%c", add(bloquePT[0]<<4, bloquePT[1]));
			else if (cont!=2) fprintf(salida, "%c%c", add(bloquePT[0]<<4, bloquePT[1]), add(bloquePT[2]<<4, bloquePT[3]));
			for(i=0;i<4;i++)extra[i]=bloqueCT[i];
			k=0;
		}
		
		c=fgetc(entrada);
		aux=splitChain(c, 2);
		
		if(cont%2==0)
		{
			bloqueCT[0]=aux[0];
			bloqueCT[1]=aux[1];
		}
		else
		{
			bloqueCT[2]=aux[0];
			bloqueCT[3]=aux[1];
		}
		k++;
	}	
	fclose(salida);
	fclose(entrada);
}


/*AES-S*/
int*EncryptAES(int bloque[], int key[])
{
	int *estado=malloc(sizeof(int)*4);
	int *subkey=malloc(sizeof(int)*3);
	
	subkey=ExpandKey(key);
	estado=AddRoundKey(bloque, splitChain(subkey[0], 4));
	estado=AddRoundKey(MixColumns(ShiftRow(NibbleSub(estado, 0)), 0), splitChain(subkey[1], 4));//ronda 1
	return AddRoundKey(ShiftRow(NibbleSub(estado, 0)), splitChain(subkey[2], 4));//ronda2
}

int*DecryptAES(int bloque[], int key[])
{
	int *estado=malloc(sizeof(int)*4);
	int *subkey=malloc(sizeof(int)*3);
	
	subkey=ExpandKey(key);
	estado=AddRoundKey(bloque, splitChain(subkey[2], 4));	
	estado=MixColumns(AddRoundKey(NibbleSub(ShiftRow(estado), 1), splitChain(subkey[1], 4)), 1);//ronda 1
	estado=AddRoundKey(NibbleSub(ShiftRow(estado), 1), splitChain(subkey[0], 4));
	return estado;
}

/*FUNCIONES AES-S*/
int*ExpandKey(int key[])
{
	int i, n=0, w[6], *subkey= malloc(sizeof(int)*3);
	w[0]=add(key[0]<<4,key[1]);
	w[1]=add(key[2]<<4,key[3]);
	w[2]=add(w[0],add(128, SubNib(RotNib(w[1]))));
	w[3]=add(w[2], w[1]);
	w[4]=add(w[2],add(48, SubNib(RotNib(w[3]))));
	w[5]=add(w[4], w[3]);
	
	for(i=0;i<3;i++){subkey[i]=(int)add(w[n]<<8, w[n+1]); n=n+2;}
	
	return subkey;
}

int*AddRoundKey(int state[], int roundkey[])
{
	int i, *estado= malloc(sizeof(int)*4);
	for(i=0;i<4;i++) estado[i]=add(state[i], roundkey[i]);
	
	return estado;
}

int*NibbleSub(int state[], int inverso)
{
	int i, *estado= malloc(sizeof(int)*4);
	if(inverso==0) for(i=0;i<4;i++) estado[i]=sbox[state[i]];//NibbleSub
	else for(i=0;i<4;i++) estado[i]=isbox[state[i]];//InverseNibbleSub
	
	return estado;
}

int*ShiftRow(int state[])
{
	int aux, *estado=state;
	aux=state[1];
	estado[1]=estado[3];
	estado[3]=aux;
	
	return estado;
}

int*MixColumns(int state[], int inverse)
{
	int a=1, b=4, i, n;
	int*estado= malloc(sizeof(int)*4);
	
	if(inverse==1){a=9;b=2;}//funcion InverseMixColumns
	for(i=0;i<4;i++)
	{
		if(i!=1 && i!=3) estado[i]=add(multiply(a, state[i], 19), multiply(b, state[i+1],19));
		else estado[i]=add(multiply(a, state[i], 19), multiply(b, state[i-1],19));
	}
	
	return estado;
}




/*OPERACIONES DE APOYO*/
int repetido(int numeros[], int tam)
{
	int i, k;
	for(i=0;i<tam;i++) for(k=i+1;k<tam;k++) if(numeros[i]==numeros[k]) return 1;
	return 0;	
}

int*CongLineal(int m, int k)
{
	int *x_k=malloc(sizeof(int)*k), i, semilla, a, c, elRep=1;
	
	//Creacion de la semilla, a y c:
	semilla=time(NULL);
	a=9;
	c=7;
	
	while(elRep==1)
	{
		for(i=0;i<k;i++)
		{
			if(i==0) x_k[0]=((a*semilla)+c)%m;
			else x_k[i]=((a*x_k[i-1])+c)%m;
		
			if(x_k[i]<0) x_k[i]=0-x_k[i];
		}elRep=repetido(x_k, k);
	}
	return x_k;
}

int*CongMult(int m, int k)
{
	int *x_k=malloc(sizeof(int)*k), i, semilla, a, elRep=1;
	
	//Creacion de la semilla, a y c:
	semilla=time(NULL);
	a=5;
	while(elRep==1)
	{
		for(i=0;i<k;i++)
		{
			if(i==0) x_k[0]=(a*semilla)%m;
			else x_k[i]=(a*x_k[i-1])%m;
		
			if(x_k[i]<0) x_k[i]=0-x_k[i];
		}elRep=repetido(x_k, k);
	}
	return x_k;
}

int*CongCuad(int m, int k)
{
	int *x_k=malloc(sizeof(int)*k), i, semilla, a, b, c, elRep=1;
	
	//Creacion de la semilla, a y c:
	semilla=time(NULL);
	a=22;
	b=17;
	c=31;
	
	while(elRep==1)
	{
		for(i=0;i<k;i++)
		{
			if(i==0) x_k[i]=((a*semilla*semilla)+(b*semilla)+c)%m;
			else x_k[i]=((a*x_k[i-1]*x_k[i-1])+(b*x_k[i-1])+c)%m;
		
			if(x_k[i]<0) x_k[i]=0-x_k[i];
		}elRep=repetido(x_k, k);
	}
	return x_k;
}

int potencia(int num, int pot)
{
	int i, res=num;
	if(pot==0) return 0;
	else if(pot==1) return num;
	else
	{
		for(i=0;i<pot-1;i++) res=res*num;
	}
	return res;
}

int*splitChain(int chain, int trozos)
{
	int*cadena= malloc(sizeof(int)*trozos), i;
	for(i=0;i<trozos;i++) cadena[i]=(chain& ( 15 << (4*(trozos-i-1)) ))>> (4*(trozos-i-1));	
	return cadena;
}

int joinChain(int chain[], int trozos)
{
	int i, cadena=0;
	for(i=0;i<trozos;i++) cadena=add(cadena, chain[i]<<(trozos*(trozos-i-1)));
	return cadena;
}

int RotNib(int word)
{
	return add((word&15)<<4,(word&240)>>4);
}

int SubNib(int word)
{
	return add(sbox[(word&240)>>4]<<4, sbox[word&15]);
}

int deg(int a)
{
	int n=1, i=0;
	while(n<=a)
	{
		i++;
		n=n*2;
	}
	return i-1;
}

int add(int a, int b)
{
	return a^b;
}

int multiply(int a, int b, int m)
{
	int i, q, a2, b2=b, n=deg(m), r=0, exp=1;
	for(i=0;i<n;i++)
	{
		a2=(a&exp)>>i;
		if(a2==1) r=r^b2;
		if(b2>>n-1==0) b2=b2<<1;
		else b2=(b2<<1)^m;
		exp=exp*2;
	}
	return r;
}

int inverse(int a, int m)
{
	int u=a, v=m, g1=1, g2=0, j, aux;
	while(u!=1)
	{
		j=deg(u)-deg(v);
		if(j<0)
		{
			aux=u; u=v; v=aux;
			aux=g1; g1=g2; g2=aux;
			j=0-j;
		}
		u=add(u, (v<<j));
		g1=add(g1, (g2<<j));
	}
	return g1;
}
