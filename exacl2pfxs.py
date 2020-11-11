#! /usr/bin/python

import sys
import ipaddress


def main():
    print('Paste the extended ACL and press CTRL+D in a new line')
    ACL_BLOCK = sys.stdin.read()
    
    #print(acl_block)
    print('\n'*10)
    ACL_PARSED = [elements.split() for elements in ACL_BLOCK.strip().splitlines()]

    #print(acl_parsed)
    
    PFXS_NAME = 'UNNAMED_PREFIX_SET'
    if ACL_PARSED[0][0] != 'ip':
        print('non-ipv4 acl detected but not supported')
        retrun
    if ACL_PARSED[0][1] != 'access-list':
        print('acl cannot be recognized')
        return
    if ACL_PARSED[0][2] != 'extended':
        print('no extended acl detected. exiting...')
        return
    if ACL_PARSED[0][3] != '':
        PFXS_NAME = ACL_PARSED[0][3]
        #print('\n The prefix-set name will be: ' + PFXS_NAME)

    PFXS = []
    #PFXS.append('prefix-set ' + PFXS_NAME)
    PFXS.append('{:<48s}{:^16s}{:<64s}'.format(PFXS_NAME, '', ' '.join(ACL_PARSED[0])))

    for i in range(1,len(ACL_PARSED)):
        #print('Parsing line : ' + str(i))
        ACE = ACL_PARSED[i]
        ACE_OFFSET = 0
        CHECK_ACE = ''
        if ACE[0] == 'deny':
            #print('End of ACL or premature deny detected. exiting.')
            if i==1:    #deny was the first ACL entry
                break
            else:
                PFXS[i-1] = PFXS[i-1].replace(',',' ')
                break
        elif ACE[0] == 'permit':
            if ACE[1] != 'ip':
                print('ACL entry contains unsupported protocol. ' + ACE[1] + ' found, but ip expected. exiting..')
                return
            else:
                
                # parse base prefix and base prefix length
                if ACE[2] == 'host':
                    PREFIX = ACE[3]
                    #LENGTH = '32'
                elif ACE[2] == 'any':
                    PREFIX = '0.0.0.0'
                    #LENGTH = '0'
                    ACE_OFFSET = 1
                else:
                    if ACE[3] == '0.0.0.0':
                        PREFIX = ACE[2]
                    else:
                        #PREFIX = ACE[2]
                        #LENGTH = str(32 -sum(bin(int(ACE[3])).count('1') for x in netmask.split('.')))
                        #CHECK_ACE.append(i)
                        print('unexpected ACE found:\n ' + ' '.join(ACE))
                        return
                
                #parse prefix range

                if ACE[4 - ACE_OFFSET] == 'any':
                    if PREFIX == '0.0.0.0':
                        LENGTH = '0 le 32'
                    else:
                        LENGTH = '32'
                    CHECK_ACE = 'CHECK'
                    #RANGE = 'le 32'
                elif ACE[4 - ACE_OFFSET] == 'host':
                    LENGTH = str(sum(bin(int(x)).count('1') for x in ACE[5 - ACE_OFFSET].split('.')))
                elif ACE[5 - ACE_OFFSET] == '0.0.0.0':
                    LENGTH = str(sum(bin(int(x)).count('1') for x in ACE[4 - ACE_OFFSET].split('.')))
                else:
                    print('unexpected ACE found:\n ' + ' '.join(ACE))
                    return

            
            #build prefix-set entry:
           
            PFXS_LINE = ' ' + PREFIX + '/' + LENGTH + ','
            PFXS_LINE = '{:<48s}{:^16s}{:<64s}'.format(PFXS_LINE, CHECK_ACE, ' '+' '.join(ACE)) 
            PFXS.append(PFXS_LINE)

        else:
            break

    
    PFXS.append('end-set')

    print('\n\n' + ('\n').join(PFXS))
    print('\n\n Thank you.')

if __name__ == '__main__':
    main()
