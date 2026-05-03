#include <iostream>     //Для ввода/вывода в консоль
#include <vector>       //Для использования vector
#include <map>          //Для хранения промежуточных результатов
#include <ctime>        //Для srand(time(0))
#include <cstdlib>      //Для rand()

using namespace std;

//ТАБЛИЦЫ ПЕРЕСТАНОВОК И S-БЛОКИ S-DES

//Перестановка 10 бит ключа
int P10[10] = {3,5,2,7,4,10,1,9,8,6};

//Получение 8-битного подключа
int P8[8] = {6,3,7,4,8,5,10,9};

//Начальная перестановка текста
int IP[8] = {2,6,3,1,4,8,5,7};

//Обратная начальная перестановка
int IP_1[8] = {4,1,3,5,7,2,8,6};

//Расширение правой части 4 бит -> 8 бит
int EP[8] = {4,1,2,3,2,3,4,1};

//Перестановка после S-блоков
int P4[4] = {2,4,3,1};

//Первый S-блок
int S0[4][4] =
{
    {1,0,3,2},
    {3,2,1,0},
    {0,2,1,3},
    {3,1,3,2}
};

//Второй S-блок
int S1[4][4] =
{
    {0,1,2,3},
    {2,0,1,3},
    {3,0,1,0},
    {2,1,0,3}
};

//ФУНКЦИЯ ПЕРЕСТАНОВКИ БИТОВ
//input  - строка из битов
//p[]    - таблица перестановки
//n      - размер таблицы
string permute(string input, int p[], int n)
{
    string output = "";

    for (int i = 0; i < n; i++)
        output += input[p[i] - 1];

    return output;
}

//ЦИКЛИЧЕСКИЙ СДВИГ ВЛЕВО
//Например:
//10101 -> 01011
string leftShift(string s, int shifts)
{
    return s.substr(shifts) + s.substr(0, shifts);
}

//XOR двух бинарных строк
//0 xor 0 = 0
//1 xor 1 = 0
//0 xor 1 = 1
//1 xor 0 = 1
string XOR(string a, string b)
{
    string result = "";

    for (int i = 0; i < a.size(); i++)
        result += (a[i] == b[i]) ? '0' : '1';

    return result;
}

//Перевод числа 0..3 в двоичный вид из 2 бит
//0 -> 00
//1 -> 01
//2 -> 10
//3 -> 11
string decToBin2(int n)
{
    string s = "";
    s += char((n / 2) + '0');
    s += char((n % 2) + '0');
    return s;
}

//ГЕНЕРАЦИЯ ПОДКЛЮЧЕЙ K1 и K2
//Из 10-битного ключа создаются два 8-битных ключа
void generateKeys(string key, string &K1, string &K2)
{
    //Переставляем биты ключа по таблице P10
    key = permute(key, P10, 10);

    //Делим ключ на две части по 5 бит
    string left = key.substr(0, 5);
    string right = key.substr(5, 5);

    //Сдвиг влево на 1
    left = leftShift(left, 1);
    right = leftShift(right, 1);

    //Формируем первый подключ K1
    K1 = permute(left + right, P8, 8);

    //Дополнительный сдвиг на 2
    left = leftShift(left, 2);
    right = leftShift(right, 2);

    //Формируем второй подключ K2
    K2 = permute(left + right, P8, 8);
}

//ОСНОВНАЯ ФУНКЦИЯ fk
//Используется внутри шифрования S-DES
string fk(string bits, string key)
{
    //Делим 8 бит на левую и правую часть
    string left = bits.substr(0,4);
    string right = bits.substr(4,4);

    //Расширяем правую часть до 8 бит
    string temp = permute(right, EP, 8);

    //XOR с подключом
    temp = XOR(temp, key);

    //Делим на 2 части по 4 бита
    string left4 = temp.substr(0,4);
    string right4 = temp.substr(4,4);

    //Работа с S0
    //row = 1 и 4 бит
    //col = 2 и 3 бит
    int row = (left4[0]-'0')*2 + (left4[3]-'0');
    int col = (left4[1]-'0')*2 + (left4[2]-'0');

    string s0 = decToBin2(S0[row][col]);

    //Работа с S1
    row = (right4[0]-'0')*2 + (right4[3]-'0');
    col = (right4[1]-'0')*2 + (right4[2]-'0');

    string s1 = decToBin2(S1[row][col]);

    //Объединяем результаты и переставляем по P4
    string p4 = permute(s0 + s1, P4, 4);

    //XOR с левой частью
    left = XOR(left, p4);

    //Возвращаем новую левую + старую правую
    return left + right;
}

//SWAP
//Меняем местами левую и правую половину abcd efgh -> efgh abcd
string SW(string bits)
{
    return bits.substr(4,4) + bits.substr(0,4);
}

//ШИФРОВАНИЕ S-DES
string encryptSDES(string plaintext, string key)
{
    string K1, K2;

    //Генерация подключей
    generateKeys(key, K1, K2);

    //Начальная перестановка
    plaintext = permute(plaintext, IP, 8);

    //Первый раунд
    plaintext = fk(plaintext, K1);

    //Перестановка половин
    plaintext = SW(plaintext);

    //Второй раунд
    plaintext = fk(plaintext, K2);

    //Финальная перестановка
    plaintext = permute(plaintext, IP_1, 8);

    return plaintext;
}

//ДЕШИФРОВАНИЕ S-DES
//Разница только порядок ключей: сначала K2 потом K1
string decryptSDES(string cipher, string key)
{
    string K1, K2;

    generateKeys(key, K1, K2);

    cipher = permute(cipher, IP, 8);
    cipher = fk(cipher, K2);
    cipher = SW(cipher);
    cipher = fk(cipher, K1);
    cipher = permute(cipher, IP_1, 8);

    return cipher;
}

//DOUBLE S-DES
//Двойное шифрование: C = E(E(M,K1),K2)
string doubleEncrypt(string M, string K1, string K2)
{
    return encryptSDES(encryptSDES(M, K1), K2);
}

//Перевод числа в бинарную строку длины n
string toBinary(int num, int n)
{
    string s = "";

    for (int i = n - 1; i >= 0; i--)
        s += ((num >> i) & 1) + '0';

    return s;
}

//АТАКА ВСТРЕЧА ПОСЕРЕДИНЕ
vector<pair<string,string>> meetInMiddle(string M, string C)
{
    //Здесь храним:
    //промежуточный результат -> список K1
    map<string, vector<string>> forward;

    //Здесь будут найденные пары ключей
    vector<pair<string,string>> result;
    
    //ШАГ 1 Шифруем M всеми K1
    for (int i = 0; i < 1024; i++)
    {
        string k1 = toBinary(i,10);

        //Получаем промежуточный текст
        string mid = encryptSDES(M, k1);

        //Сохраняем
        forward[mid].push_back(k1);
    }
    
    //ШАГ 2 Расшифровываем C всеми K2
    for (int j = 0; j < 1024; j++){
        string k2 = toBinary(j,10);

        string mid = decryptSDES(C, k2);

        //Если найдено совпадение промежуточного текста
        if (forward.count(mid))
        {
            for (auto k1 : forward[mid])
                result.push_back({k1, k2});
        }
    }

    return result;
}

int main()
{
    srand(time(0));

    //Случайные реальные ключи
    string K1 = toBinary(rand()%1024,10);
    string K2 = toBinary(rand()%1024,10);

    //Случайный открытый текст
    string M = toBinary(rand()%256,8);

    //Получаем шифртекст
    string C = doubleEncrypt(M, K1, K2);

    cout << "Истинные ключи:\n";
    cout << "K1 = " << K1 << endl;
    cout << "K2 = " << K2 << endl;

    cout << "\nОткрытый текст M = " << M << endl;
    cout << "Шифртекст C = " << C << endl;

    //Запускаем атаку
    vector<pair<string,string>> V = meetInMiddle(M,C);

    cout << "\nНайдено кандидатов: " << V.size() << endl;

    //Вывод первых 20 найденных вариантов
    for (int i = 0; i < V.size() && i < 20; i++)
    {
        cout << "K1 = " << V[i].first
             << "   K2 = " << V[i].second << endl;
    }

    //Пока не останется 1 вариант, добавляем новые пары M,C
    while (V.size() > 1)
    {
        string M2 = toBinary(rand()%256,8);
        string C2 = doubleEncrypt(M2, K1, K2);

        vector<pair<string,string>> newV;

        //Проверяем кандидатов
        for (auto p : V)
        {
            if (doubleEncrypt(M2, p.first, p.second) == C2)
                newV.push_back(p);
        }

        V = newV;

        cout << "\nПосле новой проверки осталось: "
             << V.size() << endl;
    }

    cout << "\nИТОГОВЫЙ НАЙДЕННЫЙ КЛЮЧ:\n";
    cout << "K1 = " << V[0].first << endl;
    cout << "K2 = " << V[0].second << endl;

    return 0;
}