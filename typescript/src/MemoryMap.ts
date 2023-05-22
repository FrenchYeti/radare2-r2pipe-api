

export interface  MemoryPart {
    paddr:number;
    size:number;
    vaddr:number;
    vsize:number;
    perm:string;
    sha1?:string;
    entropy?: string;
    name:string;
}

export default class MemoryMap {
    sections: MemoryPart[];
    segments: MemoryPart[];
}