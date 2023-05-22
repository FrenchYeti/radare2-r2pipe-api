

export default class Utils {

    static objToStr(pObj:any, pPrintValue:boolean = true):string {
        let str:string = '';

        if(pPrintValue)
            for (const a in pObj)  str += a + ': ' + pObj[a] + ',\n';
        else
            for (const a in pObj)  str += a + '\n';

        return str;
    }


}