package com.example.realmencryption

import android.os.Bundle
import android.util.Log
import android.widget.Button
import androidx.appcompat.app.AppCompatActivity
import com.example.realmencryption.model.Person
import com.example.realmencryption.utils.TAG
import io.realm.Realm
import io.realm.RealmConfiguration
import io.realm.RealmResults
import org.bson.types.ObjectId

class MainActivity : AppCompatActivity() {

    private var realm: Realm? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        Realm.init(this)
        getRealmInstance()

        findViewById<Button>(R.id.btnPutData).setOnClickListener {
            putPerson()
        }

        findViewById<Button>(R.id.btnGetData).setOnClickListener {
            getPersons()
        }

        findViewById<Button>(R.id.btnReset).setOnClickListener {
            KeyEncryption.resetKey(this)
            realm?.close()
        }
    }

    private fun putPerson() {
        realm?.let {
            it.executeTransactionAsync({ transactionAsync ->
                val person = transactionAsync.createObject(Person::class.java, ObjectId())
                person.name = "John"
                person.surname = "Doe"
            }, {
                Log.d(TAG(), "putPerson Success")
            }, { throwable ->
                Log.d(TAG(), "putPerson error: ${throwable.message}")
            })
        }
    }

    private fun getPersons() {
        realm?.let { realm ->
            val persons: RealmResults<Person> = realm.where(Person::class.java).findAll()
            Log.d(TAG(), "getPersons size: " + persons.size)
        }
    }

    private fun getRealmInstance() {
        try {
            val config = RealmConfiguration.Builder()
                .encryptionKey(KeyEncryption.getOrGenerateKey(this))
                .build()

            Realm.setDefaultConfiguration(config)

            realm = Realm.getInstance(config)
        } catch (exception: Exception) {
            handleRealmInitError(exception)
        }
    }

    private fun handleRealmInitError(exception: Exception) {
        Log.e(TAG(), "handleRealmInitError ${exception.message}")
        Realm.getDefaultConfiguration()?.let {
            Realm.deleteRealm(it)
        }

        getRealmInstance()
    }

}
