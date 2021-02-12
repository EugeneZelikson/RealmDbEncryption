package com.example.realmencryption.model

import io.realm.RealmObject
import io.realm.annotations.PrimaryKey
import org.bson.types.ObjectId

open class Person(
    @PrimaryKey var id: ObjectId = ObjectId(),
    var name: String? = null,
    var surname: String? = null
) : RealmObject()
