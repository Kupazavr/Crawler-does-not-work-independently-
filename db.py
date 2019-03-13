from pymongo import MongoClient
from pymongo import UpdateOne
import pymongo.errors
import logging


class DB:
    def __init__(self, db_name, db_url='mongodb://localhost'):
        self.db_name = db_name
        self.db_url = db_url
        self.client = MongoClient(db_url, connect=False)[db_name]

    @staticmethod
    def connect_to_collection(client, collection_name):
        collection = client[collection_name]
        return collection

    def get_items_from_db(self, collection_name, filtr, returning_fields=None, limit=0):
        #print("domains_limit 2: {}".format(limit))
        collection = DB.connect_to_collection(self.client, collection_name)
        items = collection.find(filtr, returning_fields).limit(limit)
        return items

    def update_items_in_db(self, collection_name, items=[], filtr=[], docs=[], upsert=True):
        collection = DB.connect_to_collection(self.client, collection_name)

        if not docs:
            docs = [UpdateOne({filtr_part: item[filtr_part] for filtr_part in filtr}, {'$set': item}, upsert=upsert) for item in items]
        try:
            logging.debug('db upload with {} items'.format(docs.__len__()))
            collection.bulk_write(docs)
        except pymongo.errors.InvalidOperation:
            logging.debug('db upload receive InvalidOperation ERROR')
        except pymongo.errors.BulkWriteError:
            logging.debug('db upload receive BulkWriteError ERROR')
            self.client = MongoClient(self.db_url, connect=False)[self.db_name]
            collection = DB.connect_to_collection(self.client, collection_name)
            collection.bulk_write(docs)
        except pymongo.errors.AutoReconnect:
            logging.debug('db upload receive AutoReconnect ERROR')
            self.client = MongoClient(self.db_url, connect=False)[self.db_name]
            collection = DB.connect_to_collection(self.client, collection_name)
            collection.bulk_write(docs)

        del docs
        return


if __name__ == '__main__':

    db = DB()
    i = db.get_items_from_db({}, returning_fields={'_id': 1}, limit=0)
    print(len(list(i)))