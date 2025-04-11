//
//  zsign.hpp
//  feather
//
//  Created by HAHALOSAH on 5/22/24.
//

#ifndef zsign_hpp
#define zsign_hpp

#include <stdio.h>
#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

bool ListDylibs(NSString *filePath, NSMutableArray *dylibPathsArray);

int zsign(NSString *app,
		  NSString *prov,
		  NSString *key,
		  NSString *pass,
		  NSString *bundleid,
		  NSString *displayname,
		  NSString *bundleversion,
		  NSArray<NSString *> *inject,
		  NSArray<NSString *> *disinject,
		  bool dontGenerateEmbeddedMobileProvision
);

#ifdef __cplusplus
}
#endif

#endif /* zsign_hpp */
