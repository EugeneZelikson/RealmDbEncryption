package com.example.realmencryption.utils

inline fun <reified T> T.TAG(): String = T::class.java.simpleName